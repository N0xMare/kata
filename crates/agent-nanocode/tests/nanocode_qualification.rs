//! The nanocode adapter's qualification cells, host-free: a mock model
//! provider (`fixtures/mock_provider.rs`, Responses over HTTP and WebSocket,
//! Messages over HTTP) and a toolhost double (`fixtures/toolhost_double.rs`)
//! speaking the toolhost protocol's frames.
//!
//! Every assertion reads a witness that does not share the adapter's code: the
//! mock's own log of the requests it received (each body, and each HTTP
//! request's head), the double's own log of the frames the worker sent, its
//! in-memory files, the test process's own working directory, the kernel's
//! account of the process's Code Mode interpreter processes, and nanocode's own
//! telemetry spans.
//!
//! Every session opens under kata's Code Mode limits as the worker installs
//! them ([`open`], `kata_agent_nanocode::install_code_mode_limits`): each cell
//! runs in an interpreter process, a confined child of this test binary
//! re-executed (`interpreter_entry!`), as it does in every kata worker.
//!
//! # The connect-failure measurement
//!
//! `a_refused_https_connect_is_marked_conservatively` and its WebSocket twin
//! record what nanocode's transport does when the provider's socket refuses the
//! connection: whether the connect happens in a `Connect` attempt (unmarked) or
//! inside the first `Generation` attempt (marked). Their docs state the
//! measured answer: on both transports the refused connect is marked.

#![allow(clippy::too_many_lines)]

#[path = "fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "fixtures/openai_turn.rs"]
mod openai_turn;
#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;
#[path = "fixtures/toolhost_double.rs"]
mod toolhost_double;

// kata's Code Mode limits, installed here as the worker installs them, run each
// cell in an interpreter process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

use std::time::Duration;

use kata_agent::adapter::session::CancelToken;
use kata_agent::adapter::{
    AgentAdapter, AttemptScope, FailedTurnCharge, MayHaveIssued, SessionSeed, TurnOutcome,
};
use kata_agent_nanocode::adapter::TestEndpoint;
use kata_agent_nanocode::{HarnessAuth, NanocodeAdapter};
use kata_toolhost_protocol::WorkerFrame;
use kata_types::agent::{HarnessCredential, Prompt};
use kata_types::cache::{TokenUsage, object_id_for_canonical_bytes};
use kata_types::effect::ProviderFailureClass;
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, CapsuleId, GuestAccess, GuestMapping, GuestPath,
};
use kata_types::primitives::ContentHash;
use mock_provider::{
    Gate, MockProvider, Reply, claude_code_reply, claude_text_reply, claude_text_reply_using,
    code_reply, empty_reply, exec_command_reply, message_reply, usage,
};
use openai_turn::{
    MODEL, RETRY_EXHAUSTION_BOUND, TURN_BOUND, bounded, cancellable_turn, exhausting_turn, openai,
    openai_prompt, scope, scope_with, turn,
};
use serde_json::{Value, json};
use toolhost_double::{
    AfterWedge, DoubleConfig, DoubleWitness, EXEC_ARRIVED, EXEC_MARKER, ExecMode, HelloMode,
    OnKill, Wedge, stop_a_background_bash_once_its_exec_arrived,
};
use ulid::Ulid;

/// Open a session over the toolhost double, under kata's Code Mode limits as
/// the worker installs them (every cell in an interpreter process).
fn open(
    adapter: &NanocodeAdapter,
    config: DoubleConfig,
) -> (Box<dyn kata_agent::adapter::AgentSession>, DoubleWitness) {
    kata_agent_nanocode::install_code_mode_limits();
    openai_turn::open(adapter, config)
}

/// [`open`] with `scope`.
fn open_scoped(
    adapter: &NanocodeAdapter,
    config: DoubleConfig,
    scope: AttemptScope,
) -> (Box<dyn kata_agent::adapter::AgentSession>, DoubleWitness) {
    kata_agent_nanocode::install_code_mode_limits();
    openai_turn::open_scoped(adapter, config, scope)
}

/// A Messages model nanocode knows, so its output-token default applies.
const CLAUDE_MODEL: &str = "claude-sonnet-4-6";

fn exec_args(cmd: &str) -> Value {
    json!({"cmd": cmd, "yield_time_ms": 30_000})
}

fn execs(witness: &DoubleWitness) -> Vec<String> {
    witness
        .frames()
        .into_iter()
        .filter_map(|frame| match frame {
            WorkerFrame::Exec {
                script, workdir, ..
            } => Some(format!("{} @ {}", script, workdir.unwrap_or_default())),
            _ => None,
        })
        .collect()
}

/// The times nanocode re-sends a Responses call whose stream failed on a
/// reconnectable error — a dropped or cut connection, a non-terminal error
/// event — whatever the endpoint's `max_attempts`: MEASURED at 8ec3b215, five
/// (its `STREAM_MAX_RETRIES`), 200 ms × 2ⁿ apart, 6.2 s in all (2ac77424 re-sent
/// none). A cell whose Responses call must fail scripts the failure this many
/// more times; a reply scripted past them is never requested.
const RECONNECTS: usize = 5;

/// `first`, a reply that fails a Responses call reconnectably, followed by
/// the [`RECONNECTS`] dropped connections that fail nanocode's re-sends of it.
fn failed_with_reconnects(first: Reply) -> Vec<Reply> {
    std::iter::once(first)
        .chain(std::iter::repeat_n(Reply::Drop, RECONNECTS))
        .collect()
}

// ── agent-turn ---------------------------------------------------------------

/// A completed turn: the model calls `exec_command`, the call reaches the
/// toolhost as an `Exec` rooted at `/work`, and the model's final message is
/// the response.
#[tokio::test]
async fn a_completed_turn_returns_the_final_message() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("printf hi > hello.txt"), usage(100, 40, 7)),
        message_reply("r2", "DONE", usage(200, 100, 3)),
    ])
    .await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("make hello.txt")).await;
    let TurnOutcome::Completed {
        response, model, ..
    } = &outcome
    else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(model.as_deref(), Some(MODEL));
    assert_eq!(execs(&witness), ["printf hi > hello.txt @ /work"]);
    assert_eq!(mock.requests().len(), 2, "one model call per response");
    let close = session.close().await;
    assert!(
        close.is_confirmed(),
        "close must confirm the toolhost exited: {close:?}"
    );
    assert!(witness.has_exited());
}

/// The same turn over the Responses WebSocket transport.
#[tokio::test]
async fn a_completed_turn_over_the_websocket_transport() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("true"), usage(10, 0, 1)),
        message_reply("r2", "DONE over ws", usage(20, 0, 1)),
    ])
    .await;
    let (mut session, witness) = open(
        &openai(&mock.url, Some(&mock.ws_url)),
        DoubleConfig::default(),
    );
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, "DONE over ws");
    assert_eq!(execs(&witness), ["true @ /work"]);
    assert!(
        mock.requests()
            .iter()
            .all(|request| request["type"] == "response.create"),
        "every WebSocket request is a response.create: {:?}",
        mock.requests()
    );
}

/// Usage is the SUM over model calls, with the provider's cached tokens taken
/// out of `input` (its `input_tokens` includes them).
#[tokio::test]
async fn usage_is_summed_per_model_call_with_cached_tokens_split_out() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("true"), usage(12_509, 6_016, 41)),
        message_reply("r2", "DONE", usage(200, 100, 3)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Completed { usage, .. } = outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(
        usage,
        Some(TokenUsage {
            input: (12_509 - 6_016) + (200 - 100),
            output: 41 + 3,
            cache_read: 6_016 + 100,
            cache_write: 0,
        })
    );
}

/// MEASURED at nanocode 1651198b, and again at each pin since, through
/// 8ec3b215: a Codex response with
/// neither a final message nor an exec or wait call does not fail the turn.
/// nanocode appends one `<empty_response>` user message and samples again, so
/// one kata turn sends a second model request, and that request's usage is
/// summed into the turn's like any other model call's. Read out of the mock's
/// own request log. At ee0f8ba1 the first empty response failed the turn
/// after one request.
#[tokio::test]
async fn an_empty_response_is_reprompted_once_and_both_calls_are_metered() {
    let mock = MockProvider::start(vec![
        empty_reply("r1", usage(300, 100, 2)),
        message_reply("r2", "DONE", usage(400, 200, 5)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Completed {
        response, usage, ..
    } = outcome
    else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, "DONE");
    let requests = mock.requests();
    assert_eq!(requests.len(), 2, "the empty response is re-prompted once");
    assert!(
        requests[1].to_string().contains("<empty_response>"),
        "the second request carries the re-prompt: {}",
        requests[1]
    );
    assert_eq!(
        usage,
        Some(TokenUsage {
            input: (300 - 100) + (400 - 200),
            output: 2 + 5,
            cache_read: 100 + 200,
            cache_write: 0,
        })
    );
}

/// **An Anthropic turn's token classes are DISJOINT.** The Messages API states
/// `input_tokens` (the uncached input), `cache_read_input_tokens` and
/// `cache_creation_input_tokens` apart; nanocode's `model.call.completed`
/// reports `input_tokens` as their SUM, with the cache read and the cache write
/// as details. kata's `input` is the uncached part alone, so a turn that wrote
/// 800 tokens of prompt cache states them once, as `cache_write` — a price
/// table charges input, cache reads and cache writes at three rates, and a
/// token bound counts each class once.
///
/// **Would red if:** the cache writes stayed inside `input` (watched: `input`
/// 1800, the 800 written tokens counted twice).
#[tokio::test]
async fn an_anthropic_turns_cache_writes_are_not_counted_as_input() {
    let mock = MockProvider::start(vec![claude_text_reply_using(
        "ok",
        json!({
            "input_tokens": 1_000,
            "cache_read_input_tokens": 5_000,
            "cache_creation_input_tokens": 800,
            "output_tokens": 1,
        }),
        300,
    )])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
    let TurnOutcome::Completed { usage, .. } = outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(
        usage,
        Some(TokenUsage {
            input: 1_000,
            output: 300,
            cache_read: 5_000,
            cache_write: 800,
        })
    );
}

/// A completed Anthropic turn: the model calls `Bash`, the call reaches the
/// toolhost as an `Exec` rooted at `/work`, and the model's final message is
/// the response. The model is the one the provider REPORTED (the mock's
/// `claude-mock`), not the one the prompt asked for.
///
/// **Would red if:** the outcome carried anything but nanocode's final message
/// (watched: an empty response).
#[tokio::test]
async fn an_anthropic_turn_returns_the_final_message() {
    let mock = MockProvider::start(vec![
        Kind::Anthropic.run("r1", "printf hi > hello.txt"),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, witness) = open(&anthropic(&mock), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &anthropic_prompt("make hello.txt")).await;
    let TurnOutcome::Completed {
        response, model, ..
    } = &outcome
    else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(model.as_deref(), Some("claude-mock"));
    assert_eq!(execs(&witness), ["printf hi > hello.txt @ /work"]);
    assert_eq!(
        mock.requests().len(),
        2,
        "one Messages request per response"
    );
    let close = session.close().await;
    assert!(
        close.is_confirmed(),
        "close must confirm the toolhost exited: {close:?}"
    );
    assert!(witness.has_exited());
}

/// An Anthropic turn's usage is the SUM over its Messages calls, each split
/// into kata's four disjoint classes: the Code Mode call and the final answer
/// each state uncached input, cache reads and cache writes apart, and each
/// call's final `output_tokens` is its `message_delta`'s.
///
/// **Would red if:** the turn kept only one call's usage (watched: the last
/// call's alone).
#[tokio::test]
async fn an_anthropic_turns_usage_is_summed_per_model_call() {
    let mock = MockProvider::start(vec![
        mock_provider::claude_code_reply_using(
            "r1",
            "text(\"looked\");",
            json!({
                "input_tokens": 1_000,
                "cache_read_input_tokens": 5_000,
                "cache_creation_input_tokens": 800,
                "output_tokens": 1,
            }),
            41,
        ),
        claude_text_reply_using(
            "DONE",
            json!({
                "input_tokens": 200,
                "cache_read_input_tokens": 100,
                "cache_creation_input_tokens": 50,
                "output_tokens": 1,
            }),
            3,
        ),
    ])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
    let TurnOutcome::Completed { usage, .. } = outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(mock.requests().len(), 2, "two Messages calls");
    assert_eq!(
        usage,
        Some(TokenUsage {
            input: 1_000 + 200,
            output: 41 + 3,
            cache_read: 5_000 + 100,
            cache_write: 800 + 50,
        })
    );
}

/// A Messages stream whose `message_start` states no `usage`.
fn claude_reply_stating_no_usage() -> Reply {
    Reply::Events(vec![
        json!({
            "type": "message_start",
            "message": {
                "id": "msg_mock", "type": "message", "role": "assistant",
                "model": "claude-mock", "content": [], "stop_reason": null,
                "stop_sequence": null,
            },
        }),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": null},
            "usage": {"output_tokens": 1},
        }),
        json!({"type": "message_stop"}),
    ])
}

/// **An Anthropic call that states no usage is never metered, and a turn on
/// which no call completed has no usage, never zero.** The Messages API
/// states usage on every response; a `message_start` without it does not
/// parse in nanocode's Messages client (MEASURED at 8ec3b215: `missing field
/// usage`), so the call FAILS rather than completing unmetered: the turn is
/// ambiguous at `ModelTokens` (the request left) and names the missing field,
/// and no second request follows it (the mock's own log). An ambiguous outcome
/// carries no usage, so the worker's metering reads it unavailable. And a turn
/// cancelled while its first request is unanswered is `Cancelled` with usage
/// `None`.
///
/// Read from nanocode's `Usage` parsers at 8ec3b215 (every class
/// `#[serde(default)]`; MEASURED at 2ac77424), and the same on the Responses
/// kind: a usage object that is present but omits a class (`{}` omits them
/// all) reads that class as 0, since nanocode's parsers default every class, so kata cannot tell an
/// omitted class from a stated zero. This cell does not claim that case.
///
/// **Would red if:** a failed call's usage were zero-filled into its outcome
/// (watched: `Cancelled` carrying a zero usage), or a turn on which no call
/// completed read a usage at all (watched: `Some` of zeros).
#[tokio::test]
async fn an_anthropic_call_stating_no_usage_is_never_metered() {
    let mock = MockProvider::start(vec![
        claude_reply_stating_no_usage(),
        claude_text_reply("must never be asked for"),
    ])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
    let TurnOutcome::Ambiguous { issued, evidence } = &outcome else {
        panic!("a call stating no usage fails, ambiguous: {outcome:?}");
    };
    assert_eq!(*issued, MayHaveIssued::ModelTokens);
    assert!(evidence.contains("missing field `usage`"), "{evidence}");
    assert_eq!(mock.requests().len(), 1, "no second request follows");

    let mock = MockProvider::start(vec![Reply::Stall]).await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let cancel = CancelToken::new();
    let prompt = anthropic_prompt("go");
    let fire = async {
        mock.wait_for_requests(1).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(
        cancellable_turn(session.as_mut(), &prompt, &cancel),
        bounded("the cancel", fire)
    );
    let TurnOutcome::Cancelled { usage } = outcome else {
        panic!("expected Cancelled, got {outcome:?}");
    };
    assert_eq!(
        usage, None,
        "no call completed: the usage is unknown, not zero"
    );
}

/// **The Anthropic kind's session id is re-derived from the seed, and the
/// agent driven runs under it.** As [`the_session_id_is_rederived_from_the_seed`]:
/// one seed opens one session id, another seed another, each the version-7
/// UUID nanocode takes. The Messages API has no session field, but nanocode's
/// API-key wire names the agent's session on every request since 8ec3b215
/// (upstream 6c44fe519, as stock Claude Code does): the
/// `x-claude-code-session-id` header and the `session_id` of
/// `metadata.user_id` ([`claude_session_identity`]), read off the requests
/// the mock RECEIVED, are the session's own id, and no request names the
/// other seed's. That is an identity, not state: every request carries the
/// turn's whole conversation, so there is no provider-side session another
/// attempt's state could be found in.
///
/// **Would red if:** the id were derived from anything but the seed (watched:
/// a re-open with the same seed naming another id), or the agent were built
/// without the session's id (watched: nanocode's own id on the wire).
#[tokio::test]
async fn the_anthropic_session_id_is_rederived_from_the_seed() {
    async fn opened(seed: u8) -> (String, Vec<(Option<String>, Option<String>)>, String) {
        let mock = MockProvider::start(vec![claude_text_reply("ok")]).await;
        let (mut session, _witness) = open_scoped(
            &anthropic(&mock),
            DoubleConfig::default(),
            scope_with(seed, 1024),
        );
        let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{outcome:?}"
        );
        let heads = mock.heads();
        let requests = mock.requests();
        let named = heads
            .iter()
            .zip(&requests)
            .map(|(head, body)| claude_session_identity(head, body))
            .collect();
        let sent: String = heads
            .into_iter()
            .chain(requests.iter().map(Value::to_string))
            .collect();
        (session.session_id().as_str().to_owned(), named, sent)
    }
    let (first, first_named, first_sent) = opened(3).await;
    let (again, again_named, again_sent) = opened(3).await;
    let (other, other_named, other_sent) = opened(4).await;
    assert_eq!(first, again, "one seed, one session id");
    assert_ne!(first, other, "another seed, another session id");
    assert_eq!(first.len(), 36, "{first}");
    assert_eq!(&first[14..15], "7", "a version-7 UUID: {first}");
    for (id, named, sent, foreign) in [
        (&first, &first_named, &first_sent, &other),
        (&again, &again_named, &again_sent, &other),
        (&other, &other_named, &other_sent, &first),
    ] {
        assert!(!named.is_empty(), "the turn sent a request");
        for identity in named {
            assert_eq!(
                identity,
                &(Some(id.clone()), Some(id.clone())),
                "the agent driven ran under another session than {id}"
            );
        }
        assert!(
            !sent.contains(foreign.as_str()),
            "the provider was told another seed's id {foreign}: {sent}"
        );
    }
}

/// The twin: the re-prompt is sent ONCE per turn. A second empty response
/// ends the turn on it: MEASURED at 8ec3b215, nanocode answers the turn with
/// an empty final message after warning "turn ended without a final message
/// or exec call after the empty-response reprompt" (its `run/turn.rs`; at
/// 2ac77424 it failed the turn `MalformedResponse`), so the turn is
/// `Completed` with an empty response and both calls' usage, and the reply
/// scripted third is never requested.
///
/// **Would red if:** the re-prompt were sent twice (watched: the third reply
/// requested), or the empty response were dropped from the usage.
#[tokio::test]
async fn a_second_empty_response_ends_the_turn_empty_without_a_third_request() {
    let mock = MockProvider::start(vec![
        empty_reply("r1", usage(10, 0, 1)),
        empty_reply("r2", usage(10, 0, 1)),
        message_reply("r3", "DONE", usage(10, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Completed {
        response, usage, ..
    } = &outcome
    else {
        panic!("a second empty response ends the turn with an empty message: {outcome:?}");
    };
    assert_eq!(response, "");
    assert_eq!(
        *usage,
        Some(TokenUsage {
            input: 20,
            output: 2,
            cache_read: 0,
            cache_write: 0,
        }),
        "both calls are metered"
    );
    assert_eq!(
        mock.requests().len(),
        2,
        "no third request after the second empty response"
    );
}

/// Typed outputs take the existing path: the final message IS the response,
/// verbatim, for the runner's output validation to read.
#[tokio::test]
async fn a_json_final_message_is_the_typed_output_response_verbatim() {
    let typed = r#"{"summary":"two files changed"}"#;
    let mock = MockProvider::start(vec![message_reply("r1", typed, usage(5, 0, 5))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("summarize")).await;
    let TurnOutcome::Completed { response, .. } = outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, typed);
    let parsed: Value = serde_json::from_str(&response).expect("the response is the JSON");
    assert_eq!(parsed["summary"], "two files changed");
}

/// The marks of a Claude Code / Claude Agent SDK request that nanocode's
/// SUBSCRIPTION wire adds (`ClaudeClient::post` under
/// `subscription_compatibility`, and `subscription_wire::prepare_with`) and its
/// API-key wire does not, each as the mock RECEIVED it. An API key's credits
/// may refuse a request that carries one: measured, the Agent SDK identity as
/// the first system block, or the `claude-code-20250219` beta, alone turns a
/// key's 200 into a 400 "credit balance is too low". The refused set:
///
/// - a header `authorization` (the OAuth bearer), `x-app`,
///   `anthropic-dangerous-direct-browser-access`, or any `x-stainless-*`; a
///   `user-agent` naming `claude-cli/`;
/// - an `anthropic-beta` token `claude-code-20250219` or `oauth-2025-04-20`;
/// - a system block whose text is the Agent SDK identity or the legacy Claude
///   Code one, or begins with the `x-anthropic-billing-header:` line;
/// - a body `metadata` naming an account (a non-empty `account_uuid` in its
///   `user_id`: the subscription's).
///
/// Not refused: the session identity nanocode's API-key wire sends on every
/// request since 8ec3b215 (upstream 6c44fe519, "as stock Claude Code 2.1.300
/// does" with an API key), the `x-claude-code-session-id` header and a
/// `metadata.user_id` with an empty `account_uuid`; [`claude_session_identity`]
/// reads them.
fn claude_code_marks(head: &str, body: &Value) -> Vec<String> {
    const IDENTITIES: [&str; 2] = [
        "You are a Claude agent, built on Anthropic's Claude Agent SDK.",
        "You are Claude Code, Anthropic's official CLI for Claude.",
    ];
    let mut marks = Vec::new();
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if matches!(
            name.as_str(),
            "authorization" | "x-app" | "anthropic-dangerous-direct-browser-access"
        ) || name.starts_with("x-stainless-")
            || (name == "user-agent" && value.contains("claude-cli/"))
        {
            marks.push(format!("header {name}"));
        }
        if name == "anthropic-beta" {
            for beta in value.split(',').map(str::trim) {
                if matches!(beta, "claude-code-20250219" | "oauth-2025-04-20") {
                    marks.push(format!("anthropic-beta {beta}"));
                }
            }
        }
    }
    for block in body["system"].as_array().into_iter().flatten() {
        let text = block["text"].as_str().unwrap_or_default();
        if IDENTITIES.contains(&text) || text.starts_with("x-anthropic-billing-header:") {
            marks.push(format!("system block {text:?}"));
        }
    }
    if let Some(metadata) = body.get("metadata") {
        let account = metadata["user_id"]
            .as_str()
            .and_then(|user| serde_json::from_str::<Value>(user).ok())
            .map(|user| user["account_uuid"].clone());
        if account != Some(json!("")) {
            marks.push(format!("body metadata {metadata}"));
        }
    }
    marks
}

/// **Each Anthropic model gets nanocode's own system blocks for that model,
/// less the Agent SDK identity**, read off the request bodies the mock
/// RECEIVED for two models nanocode prompts differently (its per-model
/// selection, `instructions::default_system_blocks`, which kata leaves to
/// nanocode and edits only on the wire, `MessagesMark`):
///
/// - `claude-sonnet-4-6`: the upstream block without the Opus 5.5 paragraph
///   ([`OPUS_5_5_PARAGRAPH`]) and closing with the total-tokens reminder
///   ([`TOTAL_TOKENS_REMINDER`]), then the Code Mode instructions and no
///   Bash-first steer;
/// - `claude-opus-5-5`: the upstream block with the Opus 5.5 paragraph and no
///   reminder, then the Code Mode instructions and nanocode's Bash-first steer
///   for that model.
///
/// Neither request carries the identity. MEASURED at 8ec3b215.
///
/// **Would red if:** kata sent one set of blocks to every model (watched: its
/// blocks before, nanocode's defaults for no model in particular: Sonnet sent
/// the Opus 5.5 paragraph and no reminder), or the wire kept the identity
/// (watched: `MessagesMark` sending the request unedited).
#[tokio::test]
async fn each_anthropic_model_gets_its_own_system_blocks_less_the_identity() {
    async fn system_sent(model: &str) -> Vec<String> {
        let mock = MockProvider::start(vec![claude_text_reply("ok")]).await;
        let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
        let mut prompt = anthropic_prompt("go");
        prompt.model_hint = Some(model.into());
        let outcome = turn(session.as_mut(), &prompt).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{model}: {outcome:?}"
        );
        let requests = mock.requests();
        assert_eq!(requests.len(), 1, "{model}: one request");
        assert_eq!(requests[0]["model"], model, "{model}: the request's model");
        requests[0]["system"]
            .as_array()
            .unwrap_or_else(|| panic!("{model}: system blocks: {}", requests[0]))
            .iter()
            .map(|block| block["text"].as_str().unwrap_or_default().to_owned())
            .collect()
    }
    let identity = nanocode_backend_claude::subscription_wire::IDENTITY;
    for (model, opus_paragraph, reminder, steered) in [
        ("claude-sonnet-4-6", false, true, false),
        ("claude-opus-5-5", true, false, true),
    ] {
        let system = system_sent(model).await;
        assert!(
            !system.iter().any(|text| text == identity),
            "{model}: the identity was sent: {system:#?}"
        );
        let upstream = &system[0];
        assert!(
            upstream.starts_with("\nYou are an agent working with the user"),
            "{model}: the upstream block opens the prompt: {upstream:?}"
        );
        assert_eq!(
            upstream.contains(OPUS_5_5_PARAGRAPH),
            opus_paragraph,
            "{model}: the Opus 5.5 paragraph"
        );
        assert_eq!(
            upstream.ends_with(TOTAL_TOKENS_REMINDER),
            reminder,
            "{model}: the total-tokens reminder"
        );
        assert!(
            system[1].starts_with("Only exec and wait are top-level tools."),
            "{model}: the Code Mode instructions follow: {:?}",
            system[1]
        );
        assert_eq!(
            system.iter().any(|text| text.contains(BASH_FIRST_STEER)),
            steered,
            "{model}: nanocode's Bash-first steer: {system:#?}"
        );
    }
}

/// The paragraph nanocode's upstream block closes with for `claude-opus-5-5`
/// alone (its `OPUS_5_5_PARAGRAPH`, 8ec3b215).
const OPUS_5_5_PARAGRAPH: &str = "\n\nDo build original games,";

/// The reminder nanocode closes its upstream block with for the models its
/// `TOTAL_TOKENS_REMINDER_MODELS` names (8ec3b215).
const TOTAL_TOKENS_REMINDER: &str = "\n\n<total_tokens>15000000 tokens left</total_tokens>";

/// How nanocode's Bash-first steer opens, the block it appends after the Code
/// Mode instructions for the models its `bash-first.json` names (8ec3b215:
/// `claude-fable-5-1` and `claude-opus-5-5`).
const BASH_FIRST_STEER: &str = "While bypass permissions mode is active:";

/// The session identity an API-key Messages request carries, as the mock
/// RECEIVED it: the `x-claude-code-session-id` header's value and the
/// `session_id` in `metadata.user_id` (a JSON string, nanocode's
/// `SubscriptionIdentity::api_metadata`).
fn claude_session_identity(head: &str, body: &Value) -> (Option<String>, Option<String>) {
    let header = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("x-claude-code-session-id")
            .then(|| value.trim().to_owned())
    });
    let metadata = body["metadata"]["user_id"]
        .as_str()
        .and_then(|user| serde_json::from_str::<Value>(user).ok())
        .and_then(|user| user["session_id"].as_str().map(str::to_owned));
    (header, metadata)
}

/// **An API-key Anthropic turn's Messages request carries no Claude Code or
/// Claude Agent SDK mark** ([`claude_code_marks`]' refused set), read out of
/// the head and body the mock provider RECEIVED. The request is still a whole
/// one: the key arrives as `x-api-key` and the system prompt is there; the
/// session identity it does carry names the session's own id. The turn is
/// ONE request: the final message ends it, with no finish check after it
/// (nanocode's Claude finish check and persistence nudge run only on a
/// `headless` agent, which kata does not build).
///
/// **Would red if:** the wire kept the Agent SDK identity that opens
/// nanocode's default system blocks (watched: `MessagesMark` sending the
/// request unedited), or its client were the subscription one.
#[tokio::test]
async fn an_api_key_anthropic_request_carries_no_claude_code_mark() {
    let mock = MockProvider::start(vec![claude_text_reply("DONE")]).await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let mut prompt = anthropic_prompt("go");
    prompt.effort_hint = Some("medium".into());
    let outcome = turn(session.as_mut(), &prompt).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let heads = mock.heads();
    let requests = mock.requests();
    assert_eq!(
        (heads.len(), requests.len()),
        (1, 1),
        "one Messages request"
    );
    assert!(
        heads[0]
            .lines()
            .any(|line| line == "x-api-key: sk-ant-mock-not-a-real-key"),
        "the key reaches the provider as x-api-key: {}",
        heads[0]
    );
    assert!(
        requests[0]["system"]
            .as_array()
            .is_some_and(|blocks| blocks.len() > 1),
        "the system prompt is sent: {}",
        requests[0]["system"]
    );
    assert_eq!(
        claude_code_marks(&heads[0], &requests[0]),
        [] as [String; 0],
        "the API-key request carries a Claude Code mark"
    );
    let id = session.session_id().as_str().to_owned();
    assert_eq!(
        claude_session_identity(&heads[0], &requests[0]),
        (Some(id.clone()), Some(id)),
        "the session identity names the session"
    );
}

/// A declared effort reaches the model request.
#[tokio::test]
async fn the_declared_effort_reaches_the_model_request() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let mut prompt = openai_prompt("go");
    prompt.effort_hint = Some("high".into());
    let outcome = turn(session.as_mut(), &prompt).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let requests = mock.requests();
    assert_eq!(
        requests[0]["reasoning"]["effort"], "high",
        "{}",
        requests[0]
    );
}

/// A prompt's output schema reaches the OpenAI Responses request as the strict
/// `text.format`, read out of the request the mock provider RECORDED; the
/// expected bytes are written out here.
#[tokio::test]
async fn an_output_schema_reaches_the_model_request_as_the_strict_text_format() {
    let schema = json!({
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"],
        "additionalProperties": false,
    });
    let mock = MockProvider::start(vec![message_reply(
        "r1",
        r#"{"summary":"s"}"#,
        usage(1, 0, 1),
    )])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let mut prompt = openai_prompt("summarize");
    prompt.output_schema = Some(schema.clone());
    let outcome = turn(session.as_mut(), &prompt).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let requests = mock.requests();
    assert_eq!(
        requests[0]["text"]["format"],
        json!({"type": "json_schema", "strict": true, "name": "kata_output", "schema": schema}),
        "{}",
        requests[0]
    );
}

/// No output schema sends no `text.format`.
#[tokio::test]
async fn no_output_schema_sends_no_text_format() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let requests = mock.requests();
    assert!(
        requests[0]["text"].get("format").is_none_or(Value::is_null),
        "{}",
        requests[0]
    );
}

/// The Anthropic kind's Messages client has no schema channel: a prompt
/// carrying one is refused by name before any model call. The turn is
/// bounded, so an un-refused turn (which reaches the mock and never settles
/// against its OpenAI-shaped reply) reds by name with the mock's request
/// count instead of as a suite timeout.
#[tokio::test]
async fn an_output_schema_on_the_anthropic_kind_is_refused_before_any_model_call() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let mut prompt = anthropic_prompt("go");
    prompt.output_schema = Some(json!({"type": "object"}));
    let outcome = tokio::time::timeout(Duration::from_secs(10), turn(session.as_mut(), &prompt))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the turn was not refused within 10 s; the mock saw {} model request(s)",
                mock.requests().len()
            )
        });
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("expected Refused, got {outcome:?}");
    };
    assert!(
        reason.starts_with("agent_output_schema_unsupported"),
        "{reason}"
    );
    assert!(
        mock.requests().is_empty(),
        "no model call before the refusal"
    );
}

/// An effort nanocode does not name is refused by name, before any model call.
#[tokio::test]
async fn an_undeclarable_effort_is_refused_before_any_model_call() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let mut prompt = openai_prompt("go");
    prompt.effort_hint = Some("ludicrous".into());
    let outcome = turn(session.as_mut(), &prompt).await;
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("expected Refused, got {outcome:?}");
    };
    assert!(reason.starts_with("agent_effort_unsupported"), "{reason}");
    assert!(
        mock.requests().is_empty(),
        "no model call before the refusal"
    );
}

/// A tty request is answered by the seam: no toolhost frame, no spawn.
#[tokio::test]
async fn a_tty_exec_is_refused_without_a_toolhost_frame() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &json!({"cmd": "vim", "tty": true}), usage(1, 0, 1)),
        message_reply("r2", "ok", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert!(
        execs(&witness).is_empty(),
        "a tty exec spawned: {:?}",
        witness.kinds()
    );
    let second = mock.requests()[1].to_string();
    assert!(
        second.contains("rerun with tty=false"),
        "the model must read the refusal: {second}"
    );
}

/// A response over the capsule's output budget is cut on a char boundary and
/// the overflow is latched.
#[tokio::test]
async fn a_response_over_the_output_budget_is_cut_and_latched() {
    let mock =
        MockProvider::start(vec![message_reply("r1", &"é".repeat(40), usage(1, 0, 1))]).await;
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope_with(7, 11),
    );
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Completed {
        response,
        response_exceeded,
        ..
    } = outcome
    else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert!(response_exceeded, "the overflow must be latched");
    assert_eq!(
        response,
        "é".repeat(5),
        "cut to 10 bytes on a char boundary"
    );
}

/// An `apply_patch` reaches the toolhost as file frames, and the double's
/// files hold the patched result.
#[tokio::test]
async fn an_apply_patch_reaches_the_toolhost_as_file_frames() {
    let patch = "*** Begin Patch\n*** Update File: /work/notes.txt\n@@\n-line two\n+line two patched\n*** Add File: /work/added.txt\n+added\n*** End Patch";
    let source = format!(
        "const result = await tools.apply_patch({});\ntext(String(result));",
        Value::from(patch)
    );
    let mock = MockProvider::start(vec![
        code_reply("r1", &source, usage(1, 0, 1)),
        message_reply("r2", "patched", usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        files: [(
            "/work/notes.txt".to_owned(),
            b"line one\nline two\n".to_vec(),
        )]
        .into(),
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("patch it")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        witness.file("/work/notes.txt").as_deref(),
        Some("line one\nline two patched\n")
    );
    assert_eq!(witness.file("/work/added.txt").as_deref(), Some("added\n"));
    assert!(
        witness.kinds().contains(&"write_file"),
        "{:?}",
        witness.kinds()
    );
}

/// A 1×1 PNG: the bytes an image read must carry unjudged.
const PIXEL_PNG: [u8; 69] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
    0x00, 0x03, 0x01, 0x01, 0x00, 0xc9, 0xfe, 0x92, 0xef, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
];

/// [`PIXEL_PNG`] as base64, which is how an image reaches the model.
const PIXEL_PNG_BASE64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

/// The Anthropic adapter over the mock's Messages endpoint.
fn anthropic(mock: &MockProvider) -> NanocodeAdapter {
    NanocodeAdapter::anthropic().with_endpoint(TestEndpoint {
        url: format!("{}/messages", mock.url),
        websocket_url: None,
    })
}

/// A prompt for the Anthropic kind.
fn anthropic_prompt(text: &str) -> Prompt {
    let mut prompt = openai_prompt(text);
    prompt.model_hint = Some(CLAUDE_MODEL.into());
    prompt.credential = Some(HarnessCredential::new(HarnessAuth::AnthropicApiKey(
        "sk-ant-mock-not-a-real-key".to_owned(),
    )));
    prompt
}

/// A nanocode kind, for the cells whose behaviour is the session's own and so
/// the same on either provider: each such cell runs once per kind, against
/// that kind's mock endpoint and in its provider's reply shapes, and names the
/// kind in every failure.
#[derive(Clone, Copy, Debug)]
enum Kind {
    OpenAi,
    Anthropic,
}

/// Both kinds, in the order the parametrised cells run them.
const KINDS: [Kind; 2] = [Kind::OpenAi, Kind::Anthropic];

impl Kind {
    /// The kind's adapter over `mock`.
    fn adapter(self, mock: &MockProvider) -> NanocodeAdapter {
        match self {
            Self::OpenAi => openai(&mock.url, None),
            Self::Anthropic => anthropic(mock),
        }
    }

    /// The kind's adapter, pointed nowhere: for a cell that refuses at `open`.
    fn unpointed(self) -> NanocodeAdapter {
        match self {
            Self::OpenAi => NanocodeAdapter::openai(),
            Self::Anthropic => NanocodeAdapter::anthropic(),
        }
    }

    /// A prompt for the kind, carrying its provider's credential.
    fn prompt(self, text: &str) -> Prompt {
        match self {
            Self::OpenAi => openai_prompt(text),
            Self::Anthropic => anthropic_prompt(text),
        }
    }

    /// A reply whose Code Mode cell runs `cmd` in the capsule in the
    /// foreground and hands its result back: `exec_command` on the Responses
    /// kind, `Bash` on the Messages kind.
    fn run(self, id: &str, cmd: &str) -> Reply {
        match self {
            Self::OpenAi => exec_command_reply(id, &exec_args(cmd), usage(1, 0, 1)),
            Self::Anthropic => claude_code_reply(
                id,
                &format!(
                    "const result = await tools.Bash({});\ntext(JSON.stringify(result));",
                    json!({"command": cmd})
                ),
            ),
        }
    }

    /// A reply that ends the turn with `text` as the model's final message.
    fn answer(self, id: &str, text: &str) -> Reply {
        match self {
            Self::OpenAi => message_reply(id, text, usage(1, 0, 1)),
            Self::Anthropic => claude_text_reply(text),
        }
    }

    /// A reply whose Code Mode cell starts `sleep 600` and returns while it
    /// still runs in the capsule, as a model's background job does:
    /// `exec_command` past a 250 ms yield on the Responses kind, a
    /// `run_in_background` `Bash` on the Messages kind. The Messages kind's
    /// cell returns only once the `Exec` reached the capsule (it polls
    /// [`EXEC_MARKER`], which [`holding`] arms): `Bash` answers before the
    /// task that sends it has run.
    fn leave_a_job_running(self, id: &str) -> Reply {
        match self {
            Self::OpenAi => leave_a_job_running(id),
            Self::Anthropic => claude_code_reply(
                id,
                &format!(
                    "await tools.Bash({{command: \"sleep 600\", run_in_background: true}});\n\
                     let arrived = false;\n\
                     for (let poll = 0; poll < 1000 && !arrived; poll++) {{\n\
                       try {{ arrived = JSON.stringify(await tools.Read({{file_path: \"{EXEC_MARKER}\"}})).includes(\"{EXEC_ARRIVED}\"); }} catch (_) {{}}\n\
                     }}\n\
                     text(arrived ? \"left running\" : \"the Exec never reached the capsule\");"
                ),
            ),
        }
    }

    /// A reply that fails the model call it answers after its request left,
    /// at once: a 400 on either kind, which neither client re-sends. Both
    /// re-send a dropped connection (MEASURED at 8ec3b215: the Responses
    /// client [`RECONNECTS`] times, the Messages client to eleven attempts in
    /// all, about 180 s of backoff).
    fn failing(self) -> Reply {
        match self {
            Self::OpenAi => Reply::Status(
                400,
                json!({"error": {"message": "mock fails this call", "type": "invalid_request_error", "param": null, "code": null}}),
            ),
            Self::Anthropic => Reply::Status(
                400,
                json!({"type": "error", "error": {"type": "invalid_request_error", "message": "mock fails this call"}}),
            ),
        }
    }
}

/// A double whose `Exec`s are answered by `execs` in order, the last
/// repeating, and that marks each `Exec`'s arrival at [`EXEC_MARKER`] (for
/// [`Kind::leave_a_job_running`]).
fn holding(execs: Vec<ExecMode>) -> DoubleConfig {
    DoubleConfig {
        execs,
        exec_marker: Some(EXEC_MARKER.to_owned()),
        ..DoubleConfig::default()
    }
}

fn pixel_in_work() -> DoubleConfig {
    DoubleConfig {
        files: [("/work/pixel.png".to_owned(), PIXEL_PNG.to_vec())].into(),
        ..DoubleConfig::default()
    }
}

/// codex's `view_image` reads the image's BYTES inside the capsule
/// (`FileHost::read_bytes` as a `ReadFile` frame, no text check), and the
/// model is handed them as a data URL, read back from the next request. The
/// cell hands the image on with Code Mode's `image()`: since 8ec3b215 a cell's
/// `text()` prints a data URL's base64 as a count ("[N base64 characters not
/// printed as text; pass the value to image() to see it]").
#[tokio::test]
async fn a_codex_view_image_reads_the_capsules_bytes_through_the_toolhost() {
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "const result = await tools.view_image({path: \"/work/pixel.png\", detail: \"original\"});\nimage(result);",
            usage(1, 0, 1),
        ),
        message_reply("r2", "seen", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, witness) = open(&openai(&mock.url, None), pixel_in_work());
    let outcome = turn(session.as_mut(), &openai_prompt("look")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert!(
        witness.frames().iter().any(
            |frame| matches!(frame, WorkerFrame::ReadFile { path, .. } if path == "/work/pixel.png")
        ),
        "the image was read inside the capsule: {:?}",
        witness.kinds()
    );
    assert!(
        mock.requests()[1].to_string().contains(PIXEL_PNG_BASE64),
        "the model is handed the capsule's bytes"
    );
}

/// claude's `Read` of an image reads its BYTES inside the capsule the same
/// way, handed on with `image()` the same way.
#[tokio::test]
async fn a_claude_image_read_reads_the_capsules_bytes_through_the_toolhost() {
    let mock = MockProvider::start(vec![
        claude_code_reply(
            "r1",
            "const result = await tools.Read({file_path: \"/work/pixel.png\"});\nimage(result);",
        ),
        claude_text_reply("seen"),
    ])
    .await;
    let (mut session, witness) = open(&anthropic(&mock), pixel_in_work());
    let outcome = turn(session.as_mut(), &anthropic_prompt("look")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert!(
        witness.frames().iter().any(
            |frame| matches!(frame, WorkerFrame::ReadFile { path, .. } if path == "/work/pixel.png")
        ),
        "the image was read inside the capsule: {:?}",
        witness.kinds()
    );
    assert!(
        mock.requests()[1].to_string().contains(PIXEL_PNG_BASE64),
        "the model is handed the capsule's bytes"
    );
}

/// **The Anthropic kind tells the model whether `/work` is a git repository
/// from the capsule.** An isolated run's agent capsule carries the git view,
/// whose `/work/.git` is the gitfile `gitdir: /git`. With that file in the
/// toolhost double's `/work`, the system context the mock Messages endpoint
/// receives says "Is a git repository: true"; without it, "false". The answer
/// is read through the toolhost (the double logs a `ReadFile` of
/// `/work/.git`), never probed on the host.
///
/// **Would red if:** the kind stated a fixed answer (it said `false` while the
/// capsule carried the git view).
#[tokio::test]
async fn the_anthropic_kind_states_the_capsules_git_repository() {
    for (gitfile, expected) in [
        (true, "Is a git repository: true"),
        (false, "Is a git repository: false"),
    ] {
        let mock = MockProvider::start(vec![claude_text_reply("ok")]).await;
        let config = DoubleConfig {
            files: if gitfile {
                [("/work/.git".to_owned(), b"gitdir: /git\n".to_vec())].into()
            } else {
                std::collections::BTreeMap::new()
            },
            ..DoubleConfig::default()
        };
        let (mut session, witness) = open(&anthropic(&mock), config);
        let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{outcome:?}"
        );
        let text = mock.requests()[0].to_string();
        assert!(
            text.contains(expected),
            "gitfile {gitfile}: the system context says {expected:?}: {text}"
        );
        assert!(
            witness.frames().iter().any(
                |frame| matches!(frame, WorkerFrame::ReadFile { path, .. } if path == "/work/.git")
            ),
            "the answer was read inside the capsule: {:?}",
            witness.kinds()
        );
    }
}

/// A claude `Bash` run in the background executes inside the capsule, and
/// `TaskOutput` hands the model what it printed.
#[tokio::test]
async fn a_background_bash_output_is_read_through_task_output() {
    let mock = MockProvider::start(vec![
        claude_code_reply(
            "r1",
            "const started = JSON.stringify(await tools.Bash({command: \"echo hi\", run_in_background: true}));\nconst id = started.match(/bash-[0-9]+/)[0];\nconst output = await tools.TaskOutput({task_id: id, block: true, timeout: 10000});\ntext(JSON.stringify(output));",
        ),
        claude_text_reply("read"),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Answer {
            stdout: "hi from the background\n".to_owned(),
            code: 0,
        }],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&anthropic(&mock), config);
    let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(execs(&witness), ["echo hi @ /work"]);
    assert!(
        mock.requests()[1]
            .to_string()
            .contains("hi from the background"),
        "TaskOutput handed the model the background command's stdout"
    );
}

/// Run [`stop_a_background_bash_once_its_exec_arrived`] against a double
/// answering the `Exec` with `exec`, and check that `TaskStop` killed the
/// `Exec`'s session before the turn's end and that the model read its answer.
async fn a_task_stop_kills_its_background_session(exec: ExecMode) {
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", &stop_a_background_bash_once_its_exec_arrived()),
        claude_text_reply("stopped"),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![exec],
        exec_marker: Some(EXEC_MARKER.to_owned()),
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&anthropic(&mock), config);
    let outcome = turn(session.as_mut(), &anthropic_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let stopped = mock.requests()[1].to_string();
    assert!(
        stopped.contains("Successfully stopped task"),
        "the model read TaskStop's answer: {stopped}"
    );
    let frames = witness.frames();
    let exec = frames
        .iter()
        .position(|frame| matches!(frame, WorkerFrame::Exec { .. }))
        .expect("the background Bash ran in the capsule");
    let WorkerFrame::Exec {
        session: started, ..
    } = &frames[exec]
    else {
        unreachable!("found above");
    };
    let killed = frames[exec..].iter().position(|frame| {
        matches!(frame, WorkerFrame::Signal { session, signal } if session == started && *signal == kata_toolhost_protocol::SignalKind::Kill)
    });
    let turn_end = frames[exec..]
        .iter()
        .position(|frame| matches!(frame, WorkerFrame::KillAll { .. }));
    assert!(
        matches!((killed, turn_end), (Some(killed), Some(turn_end)) if killed < turn_end),
        "TaskStop killed its session before the turn ended: {:?}",
        witness.kinds()
    );
}

/// `TaskStop` on a background `Bash` aborts nanocode's task, which drops the
/// seam call, and the dropped call KILLS its session in the capsule: the
/// double logs the kill for exactly that session, before the turn's end.
#[tokio::test]
async fn a_background_bash_stopped_by_task_stop_leaves_no_process() {
    a_task_stop_kills_its_background_session(ExecMode::Hold).await;
}

/// The same `TaskStop`, landing after the `Exec` was sent and before its
/// `Started` was read: the toolhost may already run the process, so the
/// dropped call kills that session too, rather than leaving it running until
/// the turn's end.
///
/// **Would red if:** the seam armed its kill only once `Started` was read
/// (watched: no `Signal` before the turn end's `KillAll`).
#[tokio::test]
async fn a_background_bash_stopped_before_its_start_is_read_is_killed() {
    a_task_stop_kills_its_background_session(ExecMode::Unstarted).await;
}

// ── uncertainty-not-reissued ------------------------------------------------

/// The FIRST Generation attempt marks the watermark `ModelTokens`, before the
/// provider answers: a deadline that drops the turn while the request is
/// outstanding reads an ambiguity at exactly that class.
#[tokio::test]
async fn the_first_generation_attempt_marks_model_tokens() {
    let mock = MockProvider::start(vec![Reply::Stall]).await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("go");
    let cancel = CancelToken::new();
    {
        let running = session.prompt(&prompt, &cancel);
        tokio::select! {
            outcome = running => panic!("the stalled turn ended: {outcome:?}"),
            () = mock.wait_for_requests(1) => {}
        }
    }
    assert_eq!(
        mock.requests().len(),
        1,
        "the request body reached the provider"
    );
    assert_eq!(session.issuance(), Some(MayHaveIssued::ModelTokens));
    assert!(
        execs(&witness).is_empty(),
        "no tool ran: the mark is the model's, not a tool's"
    );
}

/// **No model request leaves once the turn's future is dropped.** The worker
/// drops `prompt`'s future when a stop it asked for goes unconfirmed, and reads
/// `issuance()` right after; nanocode's turn "continues running when dropped".
/// Here the future is dropped while a Code Mode cell's `exec_command` is in
/// flight, with no stop asked of nanocode at all: a nanocode that does not
/// honour one. The cell yields at 1 s with its command still running, and
/// nanocode then asks the model again without waiting on any tool result: a
/// model attempt called after the stop. The mock's own log holds the one
/// request 2 s after the drop, and still one after `close`; the watermark read
/// at the drop is the one `close` leaves.
///
/// **Would red if:** dropping the future left the gate open, or a model attempt
/// nanocode calls once the gate is closed still went out (watched, each alone:
/// a second request in the mock's log after the drop).
#[tokio::test]
async fn no_model_request_leaves_once_the_turn_future_is_dropped() {
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "// @exec: {\"yield_time_ms\": 1000}\nconst ran = await tools.exec_command({\"cmd\": \"sleep 600\", \"yield_time_ms\": 30000});\ntext(JSON.stringify(ran));",
            usage(1, 0, 1),
        ),
        message_reply("r2", "must never be asked for", usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Hold],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let prompt = openai_prompt("go");
    let cancel = CancelToken::new();
    tokio::select! {
        outcome = session.prompt(&prompt, &cancel) => {
            panic!("the turn ended with its tool call in flight: {outcome:?}")
        }
        () = witness.wait_for_frames(2) => {}
    }
    let issued = session.issuance();
    assert_eq!(issued, Some(MayHaveIssued::ModelTokens));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        mock.requests().len(),
        1,
        "a model request left after the turn's future was dropped"
    );
    assert_eq!(
        session.issuance(),
        issued,
        "the watermark moved after the drop"
    );
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert!(close.is_confirmed(), "{close:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        mock.requests().len(),
        1,
        "a model request left while close ended the turn"
    );
}

/// **No Messages request leaves once the turn's future is dropped.** The
/// Anthropic kind's counterpart of
/// [`no_model_request_leaves_once_the_turn_future_is_dropped`]. A Code Mode
/// cell spins for 2 s and then returns, calling no tool (a tool call's result
/// is parked once the gate closes, `Seam::settled`, so only a cell that calls
/// none reaches the model again). The future is dropped while it spins, with
/// no stop asked of nanocode; when the cell returns, nanocode asks the model
/// again: a Messages request made after the stop. The watermark read at the
/// drop is `ModelTokens`, marked by the first request (that nothing marks
/// ahead of the prompt is
/// [`an_anthropic_turn_failing_before_any_request_is_refused`]'s claim, not
/// this cell's). The cell's return is read off the kernel's account of
/// the cell's interpreter process, a witness that shares no code with the
/// adapter: once the process that burned CPU after the drop has stopped, and a
/// second later, the mock's own log still holds the one request, and still
/// after `close`, the watermark unchanged. Waiting on the process rather than
/// on a clock keeps
/// a host that stretches the spin from passing the cell before nanocode asks.
///
/// **Would red if:** the Messages client sent a request once the gate was
/// closed (watched: a second request in the mock's log), or did not mark the
/// request it sent (watched: the watermark clean at the drop).
#[tokio::test]
async fn no_messages_request_leaves_once_the_turn_future_is_dropped() {
    let mock = MockProvider::start(vec![
        claude_code_reply(
            "r1",
            "const started = Date.now();\nwhile (Date.now() - started < 2000) {}\ntext(\"spun\");",
        ),
        claude_text_reply("must never be asked for"),
    ])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let prompt = anthropic_prompt("go");
    let cancel = CancelToken::new();
    tokio::select! {
        outcome = session.prompt(&prompt, &cancel) => {
            panic!("the turn ended with its cell spinning: {outcome:?}")
        }
        () = mock.wait_for_requests(1) => {}
    }
    let issued = session.issuance();
    assert_eq!(issued, Some(MayHaveIssued::ModelTokens));
    assert_a_code_mode_cell_runs("the dropped turn's cell, after the drop").await;
    bounded(
        "the dropped turn's cell returning",
        wait_until_no_code_mode_cell_runs(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        mock.requests().len(),
        1,
        "a Messages request left after the turn's future was dropped"
    );
    assert_eq!(
        session.issuance(),
        issued,
        "the watermark moved after the drop"
    );
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert!(close.is_confirmed(), "{close:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        mock.requests().len(),
        1,
        "a Messages request left while close ended the turn"
    );
}

/// The FIRST Messages request marks the watermark `ModelTokens` before the
/// provider answers (`MessagesMark`, inside the client, not ahead of the
/// prompt): a deadline that drops the turn while the request is outstanding
/// reads an ambiguity at exactly that class, and no tool ran.
///
/// **Would red if:** the Messages client did not mark the request it sent
/// (watched: the watermark clean with the request in the mock's log).
#[tokio::test]
async fn the_first_messages_request_marks_model_tokens() {
    let mock = MockProvider::start(vec![Reply::Stall]).await;
    let (mut session, witness) = open(&anthropic(&mock), DoubleConfig::default());
    let prompt = anthropic_prompt("go");
    let cancel = CancelToken::new();
    {
        let running = session.prompt(&prompt, &cancel);
        tokio::select! {
            outcome = running => panic!("the stalled turn ended: {outcome:?}"),
            () = mock.wait_for_requests(1) => {}
        }
    }
    assert_eq!(
        mock.requests().len(),
        1,
        "the request body reached the provider"
    );
    assert_eq!(session.issuance(), Some(MayHaveIssued::ModelTokens));
    assert!(
        execs(&witness).is_empty(),
        "no tool ran: the mark is the model's, not a tool's"
    );
}

/// **An Anthropic turn that fails before its client asks for any request is
/// refused, not ambiguous: nothing marks ahead of the prompt.** The only mark
/// is `MessagesMark`'s, taken as a request reaches the client's HTTP layer. An
/// API key that is not a valid HTTP header value fails the first request
/// while nanocode's client builds its headers, before the layer (MEASURED at
/// 8ec3b215: `Claude authentication unavailable: the Claude API key is not a
/// valid HTTP header value`). So the turn is `Refused{model_unreachable}`
/// naming nanocode's reason, the watermark is clean, and the mock's own log
/// holds no request.
///
/// **Would red if:** anything marked `ModelTokens` before the client reached
/// its layer (watched: the mark ahead of the prompt put back, `Ambiguous {
/// issued: ModelTokens, .. }`).
#[tokio::test]
async fn an_anthropic_turn_failing_before_any_request_is_refused() {
    let mock = MockProvider::start(vec![claude_text_reply("must never be asked for")]).await;
    let (mut session, witness) = open(&anthropic(&mock), DoubleConfig::default());
    let mut prompt = anthropic_prompt("go");
    prompt.credential = Some(HarnessCredential::new(HarnessAuth::AnthropicApiKey(
        "mock-key\nnot-a-header-value".to_owned(),
    )));
    let outcome = turn(session.as_mut(), &prompt).await;
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("a failure before any request is a refusal: {outcome:?}");
    };
    assert!(
        reason.starts_with("model_unreachable") && reason.contains("not a valid HTTP header value"),
        "{reason}"
    );
    assert_eq!(session.issuance(), None, "nothing was marked");
    assert!(
        mock.requests().is_empty(),
        "no request reached the provider"
    );
    assert!(execs(&witness).is_empty(), "no tool ran");
}

/// MEASURED at 8ec3b215: a Messages endpoint whose socket refuses the
/// connection. The connect happens inside the request `MessagesMark` marked
/// before it delegated, so the watermark reads `ModelTokens`, the conservative
/// residual the Responses kind's HTTPS transport has too: over-marked, never
/// under-marked. nanocode's Messages client classes a refused connect
/// transient and re-sends it (eleven attempts in all, about 180 s of backoff:
/// [`RETRY_EXHAUSTION_BOUND`]; five at 2ac77424), each through the mark, so
/// the turn ends a `Transient` provider failure charged UNKNOWN. No byte
/// reached a provider (nothing listens on the port).
#[tokio::test]
async fn a_refused_messages_connect_is_marked_conservatively() {
    let (url, _ws) = mock_provider::refused_url();
    let adapter = NanocodeAdapter::anthropic().with_endpoint(TestEndpoint {
        url: format!("{url}/messages"),
        websocket_url: None,
    });
    let (mut session, _witness) = open(&adapter, DoubleConfig::default());
    let outcome = exhausting_turn(session.as_mut(), &anthropic_prompt("go")).await;
    let TurnOutcome::ProviderFailed {
        class,
        reason,
        charge,
        ..
    } = &outcome
    else {
        panic!("a connect inside the marked request is a provider failure: {outcome:?}");
    };
    assert_eq!(*class, ProviderFailureClass::Transient);
    assert_eq!(*charge, FailedTurnCharge::Unknown);
    assert!(reason.contains("Messages transport"), "{reason}");
    assert_eq!(session.issuance(), Some(MayHaveIssued::ModelTokens));
}

/// The provider drops the connection on the Anthropic turn's request AFTER a
/// tool frame was forwarded to the toolhost. The MODEL connection's drop is
/// the provider's transient failure, not the harness's protocol going away
/// (that is the toolhost wire, whose break stays ambiguous:
/// `a_toolhost_frame_the_codec_refuses_is_named_in_the_outcome`): the turn
/// ends a `Transient` provider failure that says a tool ran, the watermark at
/// its FIRST crossing (the model call that asked for the tool), the tool's
/// frame on the double's log. MEASURED at 8ec3b215: nanocode's Messages client
/// re-sends a request whose connection dropped, eleven attempts in all, about
/// 180 s of backoff ([`RETRY_EXHAUSTION_BOUND`]; five at 2ac77424), so the
/// mock's own log holds the first call and eleven more.
///
/// **Would red if:** the Messages requests went unmarked (watched: the
/// watermark at `ToolCall`, the tool frame's mark), or the gate lost the tool
/// call (watched: `tool_called: false`).
#[tokio::test]
async fn an_anthropic_dropped_model_connection_after_a_tool_frame_is_a_transient_failure() {
    let mut script = vec![Kind::Anthropic.run("r1", "touch effect")];
    script.extend(std::iter::repeat_n(
        Reply::Drop,
        Kind::Anthropic.transient_attempts(),
    ));
    script.push(claude_text_reply("must never be asked for"));
    let mock = MockProvider::start(script).await;
    let (mut session, witness) = open(&anthropic(&mock), DoubleConfig::default());
    let outcome = exhausting_turn(session.as_mut(), &anthropic_prompt("go")).await;
    let TurnOutcome::ProviderFailed {
        class, tool_called, ..
    } = outcome
    else {
        panic!("expected ProviderFailed, got {outcome:?}");
    };
    assert_eq!(class, ProviderFailureClass::Transient);
    assert!(tool_called, "the tool frame was forwarded");
    assert_eq!(
        session.issuance(),
        Some(MayHaveIssued::ModelTokens),
        "the first crossing is the model call"
    );
    assert_eq!(execs(&witness), ["touch effect @ /work"]);
    assert_eq!(
        mock.requests().len(),
        1 + Kind::Anthropic.transient_attempts()
    );
}

/// The provider drops the model connection MID-RESPONSE on the Responses
/// kind's HTTPS transport, after a tool frame was forwarded to the toolhost:
/// the response's head declared its whole body, and the connection closed
/// after every event but the terminal one, on the call and on every re-send of
/// it. MEASURED at 8ec3b215: nanocode reports the cut as a transport failure
/// it advises retrying ("request or response body error: connection closed
/// before message completed", `ResponsesError::HttpRequest { retryable: true
/// }`), re-sends the call [`RECONNECTS`] times, and ends the turn on the last
/// cut; so the cut is the provider's TRANSIENT failure, as the Messages
/// client's stream that ended early already was: the turn ends
/// `ProviderFailed` classed `Transient`, saying a tool ran, the watermark at its
/// FIRST crossing (the model call that asked for the tool). The mock's own log
/// holds the first call, the cut one and its re-sends, and no more. (At
/// 2ac77424 nanocode reported the cut as `error decoding response body` with
/// no retry advice and re-sent nothing, and the turn ended `Ambiguous`.)
///
/// **Would red if:** the adapter classified the failure by the bytes that left
/// rather than by nanocode's typed error (the turn `Ambiguous`), or the gate
/// lost the tool call (`tool_called: false`).
#[tokio::test]
async fn a_model_connection_dropped_mid_response_is_a_transient_failure() {
    let Reply::Events(answer) = message_reply("r2", "DONE", usage(1, 0, 1)) else {
        unreachable!("a message reply is a stream of events")
    };
    let mut script = vec![Kind::OpenAi.run("r1", "touch effect")];
    script.extend(std::iter::repeat_n(
        Reply::DropMidResponse(answer),
        1 + RECONNECTS,
    ));
    script.push(message_reply(
        "r3",
        "must never be asked for",
        usage(1, 0, 1),
    ));
    let mock = MockProvider::start(script).await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::ProviderFailed {
        class,
        reason,
        tool_called,
        ..
    } = outcome
    else {
        panic!("a cut response is the provider's transient failure: {outcome:?}");
    };
    assert_eq!(class, ProviderFailureClass::Transient, "{reason}");
    assert!(
        reason.contains("connection closed before message completed"),
        "the reason is nanocode's own account of the cut: {reason}"
    );
    assert!(tool_called, "the tool frame was forwarded");
    assert_eq!(
        session.issuance(),
        Some(MayHaveIssued::ModelTokens),
        "the first crossing is the model call"
    );
    assert_eq!(execs(&witness), ["touch effect @ /work"]);
    assert_eq!(
        mock.requests().len(),
        2 + RECONNECTS,
        "the cut request is re-sent as nanocode reconnects, and no more"
    );
}

/// **A failed turn any of whose attempts nanocode re-sent is charged UNKNOWN,
/// never the part kata metered.** A re-sent attempt may be one whose stream
/// was cut after the provider billed it, and no event reports an unfinished
/// attempt's usage, so the completed calls' usage would under-count what was
/// billed. Two shapes, each read off the mock's own log:
///
/// * the Responses kind's first call completes, reporting its usage, after a
///   tool ran; the mock then cuts the second call's response mid-body (its text
///   streamed, its terminal `response.completed`, which would report usage,
///   never sent) on the call and on each of nanocode's [`RECONNECTS`] re-sends:
///   `Transient`, charged `Unknown`, not the first call's usage;
/// * on either kind the turn's one call is answered 500, re-sent, and refused
///   400 for credit: `Refused`, charged `Unknown`, not the authoritative `0` a
///   refusal of a request sent once is.
///
/// **Would red if:** the charge counted only the completed calls (watched, the
/// charge before: `Metered` with the first call's usage for the cut, `Nothing`
/// for the re-sent refusal).
#[tokio::test]
async fn a_failed_turn_with_a_resent_attempt_is_charged_unknown() {
    let Reply::Events(answer) = message_reply("r2", "DONE", usage(1, 0, 1)) else {
        unreachable!("a message reply is a stream of events")
    };
    let mut script = vec![Kind::OpenAi.run("r1", "true")];
    script.extend(std::iter::repeat_n(
        Reply::DropMidResponse(answer),
        1 + RECONNECTS,
    ));
    let mock = MockProvider::start(script).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::ProviderFailed { class, charge, .. } = &outcome else {
        panic!("a cut response is the provider's transient failure: {outcome:?}");
    };
    assert_eq!(*class, ProviderFailureClass::Transient);
    assert_eq!(
        *charge,
        FailedTurnCharge::Unknown,
        "the cut stream's billing is unseen"
    );
    assert_eq!(mock.requests().len(), 2 + RECONNECTS);

    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.server_error(), kind.credit_refusal()]).await;
        let (mut session, _witness) = open(&kind.adapter(&mock), DoubleConfig::default());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::ProviderFailed { class, charge, .. } = &outcome else {
            panic!("{kind:?}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{kind:?}");
        assert_eq!(
            *charge,
            FailedTurnCharge::Unknown,
            "{kind:?}: an attempt was re-sent"
        );
        assert_eq!(
            mock.requests().len(),
            2,
            "{kind:?}: the 500, then its re-send"
        );
    }
}

/// An operator cancel nanocode confirms on the Anthropic kind, with a `Bash`
/// in flight in the capsule, is `Cancelled`, carrying the usage the model
/// call before it reported, and `close` reports nanocode acknowledged it. No
/// model request follows the cancel (the mock's own log). The command is one
/// that never ends, not a `sleep`: nanocode's Claude `Bash` refuses a
/// standalone `sleep` of two seconds or more before it runs (MEASURED at
/// 8ec3b215: "Blocked: standalone sleep 60"), so no `Exec` would reach the
/// capsule.
///
/// **Would red if:** a confirmed cancel dropped the usage observed so far
/// (watched: `Cancelled{usage: None}`).
#[tokio::test]
async fn an_anthropic_confirmed_cancel_carries_partial_usage() {
    let mock = MockProvider::start(vec![
        Kind::Anthropic.run("r1", "tail -f /dev/null"),
        claude_text_reply("must never be asked for"),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Hold],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&anthropic(&mock), config);
    let cancel = CancelToken::new();
    let prompt = anthropic_prompt("go");
    let fire = async {
        while !witness.kinds().contains(&"exec") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(
        cancellable_turn(session.as_mut(), &prompt, &cancel),
        bounded("the cancel", fire)
    );
    let TurnOutcome::Cancelled { usage } = outcome else {
        panic!("expected Cancelled, got {outcome:?}");
    };
    assert_eq!(
        usage,
        Some(TokenUsage {
            input: 10,
            output: 3,
            cache_read: 0,
            cache_write: 0,
        })
    );
    assert_eq!(
        mock.requests().len(),
        1,
        "no model request after the cancel"
    );
    let close = session.close().await;
    assert!(
        close.harness_acknowledged_cancel(),
        "nanocode confirmed the operator's cancel: {close:?}"
    );
}

/// MEASURED: a stop at the wall deadline while the WebSocket handshake is still
/// unanswered, nanocode's `Connect` attempt in flight. On nanocode 8c8f8485, and
/// again at each pin since, through 8ec3b215, the `Generation` attempt is CALLED
/// before that handshake answers (both attempts reach [`IssuanceMark`] at once,
/// the body waiting on the socket), so the watermark is already `ModelTokens`
/// when the worker reads it: the stop is ambiguous, never a
/// provably-not-performed one, whether nanocode confirms
/// the cancel within the grace (it does, here) or the future is dropped with
/// none asked. Either way the worker's verdict and the mock's own log agree: a
/// read that found the watermark clean would require no request to have
/// reached the mock, before or after the handshake is let through. A nanocode
/// bump that calls `Generation` only once connected turns the read clean and
/// the measured `Some` red; the cell then rests on the refusal, which keeps the
/// mock's log empty.
#[tokio::test]
async fn a_stop_with_the_connect_in_flight_reads_the_watermark_crossed() {
    for drop_unasked in [false, true] {
        let mock = MockProvider::start_holding_websocket(vec![message_reply(
            "r1",
            "must never be asked for",
            usage(1, 0, 1),
        )])
        .await;
        let (mut session, _witness) = open(
            &openai(&mock.url, Some(&mock.ws_url)),
            DoubleConfig::default(),
        );
        let prompt = openai_prompt("go");
        let cancel = CancelToken::new();
        {
            let running = session.prompt(&prompt, &cancel);
            tokio::pin!(running);
            tokio::select! {
                outcome = &mut running => panic!("the turn ended before it connected: {outcome:?}"),
                () = mock.wait_for_held_handshake() => {}
            }
            if !drop_unasked {
                // The worker's deadline: the token, then its grace.
                cancel.cancel();
                drop(tokio::time::timeout(Duration::from_secs(5), &mut running).await);
            }
        }
        let issued = session.issuance();
        mock.release_handshakes();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let close = tokio::time::timeout(Duration::from_secs(30), session.close())
            .await
            .expect("close is bounded");
        assert!(close.is_confirmed(), "{close:?}");
        assert!(
            issued.is_some() || mock.requests().is_empty(),
            "drop_unasked={drop_unasked}: the watermark read clean and the mock received {:?}",
            mock.requests()
        );
        assert_eq!(
            issued,
            Some(MayHaveIssued::ModelTokens),
            "drop_unasked={drop_unasked}: MEASURED, the Generation attempt is called before the \
             handshake answers"
        );
    }
}

/// MEASURED: a provider whose socket refuses the connection, on the HTTPS
/// transport. nanocode issues no `Connect` attempt on HTTPS: its one
/// `Generation` attempt opens the connection itself, so the mark that attempt
/// takes before it delegates (the request body could leave inside it) covers
/// a connect that never succeeded: the watermark reads `ModelTokens`, the
/// conservative residual, over-marked, never under-marked. nanocode classes the
/// refused connect transient, so the turn ends a `Transient` provider failure,
/// charged UNKNOWN (no call completed), never the clean watermark's
/// `model_unreachable`. No byte reached a provider (nothing listens on the
/// port). A nanocode bump that moves the connect into an attempt of its own
/// turns this red, and the cell then asserts the refusal instead.
#[tokio::test]
async fn a_refused_https_connect_is_marked_conservatively() {
    let (url, _ws) = mock_provider::refused_url();
    let (mut session, _witness) = open(&openai(&url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::ProviderFailed {
        class,
        reason,
        charge,
        ..
    } = &outcome
    else {
        panic!("a connect inside the Generation attempt is marked: {outcome:?}");
    };
    assert_eq!(*class, ProviderFailureClass::Transient);
    assert_eq!(*charge, FailedTurnCharge::Unknown);
    assert!(
        reason.contains("Responses HTTPS request failed"),
        "{reason}"
    );
    assert_eq!(session.issuance(), Some(MayHaveIssued::ModelTokens));
}

/// MEASURED: the same on the WebSocket transport. Here nanocode DOES connect
/// in a `Connect` attempt of its own, which the mark skips, and that attempt
/// fails unmarked; but nanocode then falls back to HTTPS for the session, and
/// the HTTPS `Generation` attempt connects inside itself as above. So a
/// refused WebSocket is marked too, and the turn's failure is the HTTPS
/// request's, not the socket's: a `Transient` provider failure.
#[tokio::test]
async fn a_refused_websocket_connect_falls_back_and_is_marked_conservatively() {
    let (url, ws) = mock_provider::refused_url();
    let (mut session, _witness) = open(&openai(&url, Some(&ws)), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::ProviderFailed { class, reason, .. } = &outcome else {
        panic!("the HTTPS fallback's Generation attempt is marked: {outcome:?}");
    };
    assert_eq!(*class, ProviderFailureClass::Transient);
    assert!(
        reason.contains("Responses HTTPS request failed"),
        "{reason}"
    );
    assert_eq!(session.issuance(), Some(MayHaveIssued::ModelTokens));
}

/// **The two refused cells' address is refused by the KERNEL, and nothing in a
/// parallel run can take it.** Asked of the socket layer, not of nanocode: the
/// fixture's address does not bind in this (unprivileged) process, and a
/// connect to it is refused rather than queued or answered.
///
/// **Would red if:** `refused_url` went back to a port read off a dropped
/// `127.0.0.1:0` listener — that port binds again at once, which is how another
/// cell's mock once took it and answered the refused HTTPS cell `Completed`.
#[tokio::test]
async fn the_refused_address_cannot_be_taken_and_refuses_every_connect() {
    let (url, ws) = mock_provider::refused_url();
    let addr = url
        .strip_prefix("http://")
        .and_then(|rest| rest.strip_suffix("/v1"))
        .expect("an http://<addr>/v1 url");
    assert_eq!(ws, format!("ws://{addr}/v1/responses"), "one address");
    let bind = tokio::net::TcpListener::bind(addr).await.map(|_| ());
    assert_eq!(
        bind.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "{addr} must not be bindable by an unprivileged process"
    );
    let connect = tokio::net::TcpStream::connect(addr).await.map(|_| ());
    assert_eq!(
        connect.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::ConnectionRefused),
        "a connect to {addr} is refused"
    );
}

/// **Either kind records each tool call's result by its id and status.** One
/// turn per kind: the model's one call is a Code Mode `exec` cell that runs
/// `true` through the kind's shell tool (`exec_command`, `Bash`), which the
/// double answers with exit 0, and its second request gets the final answer.
/// The turn's evidence records a `ToolResult` for the `exec` call, `completed`,
/// under the very id the model gave it (`call_r1`, `toolu_r1`) and which the
/// mock's own log of the second request answers, and a `completed` result for
/// the nested shell call; every result's id is a recorded `ToolCall`'s. The
/// two kinds' records have the same shape.
///
/// **Would red if:** a kind's `tool.result` payload were not read for its id
/// and status (watched: before the fold read only those two fields, the
/// Messages kind recorded no `ToolResult` at all, its `result` being
/// `{text}`/`{content_blocks}` rather than the Responses kind's tool output).
#[tokio::test]
async fn a_tool_result_is_recorded_on_either_kind() {
    use kata_types::agent::SessionEvidenceEvent;

    let mut shapes = Vec::new();
    for kind in KINDS {
        let mock =
            MockProvider::start(vec![kind.run("r1", "true"), kind.answer("r2", "done")]).await;
        let (mut session, _witness) = open(&kind.adapter(&mock), DoubleConfig::default());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{kind:?}: {outcome:?}"
        );
        let exec = match kind {
            Kind::OpenAi => "call_r1",
            Kind::Anthropic => "toolu_r1",
        };
        let requests = mock.requests();
        assert_eq!(requests.len(), 2, "{kind:?}");
        assert!(
            requests[1].to_string().contains(exec),
            "{kind:?}: the second request answers `{exec}`: {}",
            requests[1]
        );
        let events = session.take_evidence().events;
        let calls: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                SessionEvidenceEvent::ToolCall { id } => Some(id.to_string()),
                _ => None,
            })
            .collect();
        let results: Vec<(String, String)> = events
            .iter()
            .filter_map(|event| match event {
                SessionEvidenceEvent::ToolResult { id, status } => {
                    Some((id.to_string(), status.to_string()))
                }
                _ => None,
            })
            .collect();
        assert!(
            results.contains(&(exec.to_owned(), "completed".to_owned())),
            "{kind:?}: the `exec` call's result is recorded: {results:?} of {events:?}"
        );
        assert_eq!(
            results.len(),
            2,
            "{kind:?}: the `exec` cell's and its shell call's results: {results:?}"
        );
        assert!(
            results
                .iter()
                .all(|(id, status)| status == "completed" && calls.contains(id)),
            "{kind:?}: every result is `completed` and answers a recorded call: \
             {results:?} of {calls:?}"
        );
        shapes.push((calls.len(), results.len()));
    }
    assert_eq!(shapes[0], shapes[1], "both kinds record the same shape");
}

/// The provider drops the connection on the request AFTER a tool frame was
/// forwarded to the toolhost. The model connection's drop is the provider's
/// transient failure, not the harness's protocol going away (the toolhost
/// wire, whose break stays ambiguous:
/// `a_toolhost_eof_mid_turn_cancels_the_turn_and_is_ambiguous`): the turn
/// ends a `Transient` provider failure that says a tool ran, the watermark at
/// its FIRST crossing (the model call that asked for the tool), and the tool's
/// frame on the double's log.
#[tokio::test]
async fn a_dropped_model_connection_after_a_tool_frame_is_a_transient_failure() {
    let mut script = vec![exec_command_reply(
        "r1",
        &exec_args("touch effect"),
        usage(1, 0, 1),
    )];
    script.extend(failed_with_reconnects(Reply::Drop));
    let mock = MockProvider::start(script).await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::ProviderFailed {
        class, tool_called, ..
    } = outcome
    else {
        panic!("expected ProviderFailed, got {outcome:?}");
    };
    assert_eq!(class, ProviderFailureClass::Transient);
    assert!(tool_called, "the tool frame was forwarded");
    assert_eq!(
        session.issuance(),
        Some(MayHaveIssued::ModelTokens),
        "the first crossing is the model call"
    );
    assert_eq!(execs(&witness), ["touch effect @ /work"]);
    assert_eq!(
        mock.requests().len(),
        2 + RECONNECTS,
        "the dropped request and nanocode's re-sends of it"
    );
}

/// How long the session gives nanocode to confirm a stop it asked for
/// (`TURN_CANCEL_GRACE` in `session.rs`): a stop nothing confirms ends the
/// turn only once it expires.
const NANOCODE_CANCEL_GRACE: Duration = Duration::from_secs(5);

/// The toolhost's stdout ends while a tool call is in flight: the latch
/// cancels the turn, the turn is ambiguous, and the model's next request never
/// reaches the provider (the mock's own log).
///
/// The cancel is read off the turn's duration. Two mechanisms keep the model
/// from being asked again, and either alone does: the latch's stop (the gate
/// closes and nanocode is cancelled), and the seam, which parks a call that
/// ends on a broken wire until the turn has ended (`Seam::settled`). So the
/// request count does not see the stop. Without it nanocode confirms no
/// cancel, and the drive loop ends the turn only once the grace it arms at the
/// latch, after the double closed its stdout, has expired; with it the turn
/// ends inside [`NANOCODE_CANCEL_GRACE`] of that close (the double's own
/// clock read, `DoubleWitness::stdout_closed_at`).
///
/// **Would red if:** the latch did not cancel the turn (watched: with the latch
/// arm's `stop_turn` removed, the turn ends on the grace, past the bound).
#[tokio::test]
async fn a_toolhost_eof_mid_turn_cancels_the_turn_and_is_ambiguous() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("true"), usage(1, 0, 1)),
        message_reply("r2", "must never be asked for", usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::CloseStdout],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let ended = std::time::Instant::now();
    let TurnOutcome::Ambiguous { issued, evidence } = &outcome else {
        panic!("expected Ambiguous, got {outcome:?}");
    };
    assert_eq!(*issued, MayHaveIssued::ModelTokens);
    assert!(evidence.contains("toolhost_lost"), "{evidence}");
    let closed = witness
        .stdout_closed_at()
        .expect("the double closed its stdout on the exec");
    let stopped_in = ended.saturating_duration_since(closed);
    assert!(
        stopped_in < NANOCODE_CANCEL_GRACE,
        "the latched turn ended {stopped_in:?} after the toolhost's stdout closed, not \
         inside nanocode's {NANOCODE_CANCEL_GRACE:?} cancel grace: no stop the latch asked \
         for was confirmed"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        mock.requests().len(),
        1,
        "the next model request must never be sent"
    );
    let close = session.close().await;
    assert!(
        !close.harness_acknowledged_cancel(),
        "a latch's stop is kata's seam asking, never a cancel nanocode acknowledged: {close:?}"
    );
}

/// After the latch, and after a cancel, no tool frame is sent: read from the
/// double's own log of what the worker wrote.
#[tokio::test]
async fn no_tool_frame_is_sent_after_cancel_or_a_latch() {
    // The latch: the toolhost answers the first exec with an `Error` frame.
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("first"), usage(1, 0, 1)),
        exec_command_reply("r2", &exec_args("second"), usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::ErrorFrame],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Ambiguous { .. }),
        "{outcome:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        witness.kinds(),
        ["read_file", "exec"],
        "nothing may follow the frame the toolhost refused"
    );
    assert_eq!(mock.requests().len(), 1);

    // The cancel: the exec holds, the operator cancels; only the kill follows.
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("sleep 60"), usage(1, 0, 1)),
        exec_command_reply("r2", &exec_args("second"), usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Hold],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let cancel = CancelToken::new();
    let prompt = openai_prompt("go");
    let fire = async {
        witness.wait_for_frames(2).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(
        cancellable_turn(session.as_mut(), &prompt, &cancel),
        bounded("the cancel", fire)
    );
    assert!(
        matches!(outcome, TurnOutcome::Cancelled { .. }),
        "{outcome:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let kinds = witness.kinds();
    assert_eq!(kinds[..2], ["read_file", "exec"], "{kinds:?}");
    assert!(
        kinds[2..]
            .iter()
            .all(|kind| *kind == "kill_all" || *kind == "signal"),
        "only kills may follow the cancel: {kinds:?}"
    );
    assert!(
        kinds[2..].contains(&"kill_all"),
        "the cancel reached the capsule: {kinds:?}"
    );
    assert!(
        witness.frames().iter().all(|frame| match frame {
            WorkerFrame::Signal { signal, .. } =>
                *signal == kata_toolhost_protocol::SignalKind::Kill,
            _ => true,
        }),
        "every signal after the cancel is a kill"
    );
    assert_eq!(mock.requests().len(), 1);
}

/// **Behind kata's backend, a cancel that lands inside a native step is
/// confirmed.** The model's one request starts a Code Mode cell that, inside
/// its 60 s yield, runs one long native sort
/// ([`quickjs_threads::A_LONG_NATIVE_STEP`]), which no interrupt reaches; the
/// operator cancels once the kernel's account sees the cell's interpreter
/// process burn CPU. The cancel's terminate kills that process, so nanocode
/// confirms the cancel: the turn is `Cancelled`, `close` reports the
/// acknowledged cancel, one model request left, and the kernel lists no
/// interpreter process of this one afterwards. On the engine's own thread the
/// step holds nanocode unconfirmed instead
/// (`nanocode_thread_backend::an_unconfirmed_cancel_is_ambiguous_at_the_crossed_class`).
///
/// **Would red if:** the cell ran on the engine's thread (watched, with the
/// limits not installed: the witness sees no interpreter process; that
/// configuration's turn is ambiguous, nanocode confirming nothing, as
/// `nanocode_thread_backend` pins).
#[tokio::test]
async fn a_cancel_during_a_native_step_is_confirmed_behind_kata_backend() {
    let mock = MockProvider::start(vec![code_reply(
        "r1",
        &format!(
            "// @exec: {{\"yield_time_ms\": 60000}}\n{}",
            quickjs_threads::A_LONG_NATIVE_STEP
        ),
        usage(1, 0, 1),
    )])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let cancel = CancelToken::new();
    let prompt = openai_prompt("sort");
    let fire = async {
        mock.wait_for_requests(1).await;
        assert_a_code_mode_cell_runs("before the cancel").await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(cancellable_turn(session.as_mut(), &prompt, &cancel), fire);
    assert!(
        matches!(outcome, TurnOutcome::Cancelled { .. }),
        "the cancel's terminate ended the step, and nanocode confirmed: {outcome:?}"
    );
    assert_eq!(mock.requests().len(), 1, "one model request left");
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert!(
        close.harness_acknowledged_cancel(),
        "nanocode confirmed the cancel: {close:?}"
    );
    assert!(
        quickjs_threads::interpreters().is_empty(),
        "the step's interpreter was reaped: {:?}",
        quickjs_threads::interpreters()
    );
}

/// An operator cancel nanocode confirms is `Cancelled`, carrying the usage the
/// model calls before it reported.
#[tokio::test]
async fn a_confirmed_cancel_carries_partial_usage() {
    let mock = MockProvider::start(vec![exec_command_reply(
        "r1",
        &exec_args("sleep 60"),
        usage(300, 100, 9),
    )])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Hold],
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let cancel = CancelToken::new();
    let prompt = openai_prompt("go");
    let fire = async {
        witness.wait_for_frames(2).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(
        cancellable_turn(session.as_mut(), &prompt, &cancel),
        bounded("the cancel", fire)
    );
    let TurnOutcome::Cancelled { usage } = outcome else {
        panic!("expected Cancelled, got {outcome:?}");
    };
    assert_eq!(
        usage,
        Some(TokenUsage {
            input: 200,
            output: 9,
            cache_read: 100,
            cache_write: 0,
        })
    );
    let close = session.close().await;
    assert!(
        close.harness_acknowledged_cancel(),
        "nanocode confirmed the operator's cancel: {close:?}"
    );
}

// ── turn end -------------------------------------------------------------------

/// A Code Mode cell that starts a command and returns while it still runs
/// (yield 250 ms): the command is left live in the capsule past its tool call,
/// as a model's background job is.
fn leave_a_job_running(id: &str) -> Reply {
    exec_command_reply(
        id,
        &json!({"cmd": "sleep 600", "yield_time_ms": 250}),
        usage(1, 0, 1),
    )
}

/// Read RIGHT AFTER `prompt` returned, before `close`: the turn's end killed
/// every capsule process. On a wire that still works the double logged a
/// `KillAll`; on a broken one the worker dropped the double's stdin instead.
/// Either way no session is live.
fn assert_the_turn_end_killed_everything(witness: &DoubleWitness, path: &str, latched: bool) {
    if latched {
        assert!(
            witness.stdin_closed(),
            "{path}: the latched turn dropped the toolhost's stdin"
        );
    } else {
        assert!(
            witness.kinds().contains(&"kill_all"),
            "{path}: the turn ended without a KillAll: {:?}",
            witness.kinds()
        );
    }
    assert!(
        witness.live_sessions().is_empty(),
        "{path}: a capsule process outlived the turn: {:?}",
        witness.live_sessions()
    );
}

/// **Every turn end kills the capsule's processes BEFORE the outcome, on
/// either kind.** On each path a turn can end by (completed, failed, refused
/// after the handshake, cancelled by the operator, latched) the double is read
/// the instant `prompt` returns: a job the model left running (its `Exec` on
/// the double's log) is gone, and the gate is closed, so nothing follows.
#[tokio::test]
async fn every_turn_end_kills_the_capsules_processes_before_the_outcome() {
    for kind in KINDS {
        let hold = || holding(vec![ExecMode::Hold]);
        let ran_a_job = |witness: &DoubleWitness, path: &str| {
            assert!(
                witness.kinds().contains(&"exec"),
                "{kind:?} {path}: the job reached the capsule: {:?}",
                witness.kinds()
            );
        };

        // Completed, with a job left running.
        let mock = MockProvider::start(vec![
            kind.leave_a_job_running("r1"),
            kind.answer("r2", "done"),
        ])
        .await;
        let (mut session, witness) = open(&kind.adapter(&mock), hold());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{kind:?}: {outcome:?}"
        );
        ran_a_job(&witness, "completed");
        assert_the_turn_end_killed_everything(&witness, &format!("{kind:?} completed"), false);

        // Failed: the provider fails the next call.
        let mock = MockProvider::start(vec![kind.leave_a_job_running("r1"), kind.failing()]).await;
        let (mut session, witness) = open(&kind.adapter(&mock), hold());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(
                outcome,
                TurnOutcome::ProviderFailed {
                    tool_called: true,
                    ..
                }
            ),
            "{kind:?}: {outcome:?}"
        );
        ran_a_job(&witness, "failed");
        assert_the_turn_end_killed_everything(&witness, &format!("{kind:?} failed"), false);

        // Refused after the handshake: no credential.
        let mock = MockProvider::start(Vec::new()).await;
        let (mut session, witness) = open(&kind.adapter(&mock), hold());
        let mut prompt = kind.prompt("go");
        prompt.credential = None;
        let outcome = turn(session.as_mut(), &prompt).await;
        assert!(
            matches!(outcome, TurnOutcome::Refused { .. }),
            "{kind:?}: {outcome:?}"
        );
        assert_the_turn_end_killed_everything(&witness, &format!("{kind:?} refused"), false);

        // Cancelled by the operator while the job runs and the model is asked
        // again.
        let mock = MockProvider::start(vec![kind.leave_a_job_running("r1"), Reply::Stall]).await;
        let (mut session, witness) = open(&kind.adapter(&mock), hold());
        let cancel = CancelToken::new();
        let prompt = kind.prompt("go");
        let fire = async {
            mock.wait_for_requests(2).await;
            cancel.cancel();
        };
        let (outcome, ()) = tokio::join!(
            cancellable_turn(session.as_mut(), &prompt, &cancel),
            bounded("the cancel", fire)
        );
        assert!(
            matches!(
                outcome,
                TurnOutcome::Cancelled { .. } | TurnOutcome::Ambiguous { .. }
            ),
            "{kind:?}: {outcome:?}"
        );
        ran_a_job(&witness, "cancelled");
        assert_the_turn_end_killed_everything(&witness, &format!("{kind:?} cancelled"), false);

        // Latched: the job runs, then the toolhost refuses the next exec.
        let mock =
            MockProvider::start(vec![kind.leave_a_job_running("r1"), kind.run("r2", "next")]).await;
        let (mut session, witness) = open(
            &kind.adapter(&mock),
            holding(vec![ExecMode::Hold, ExecMode::ErrorFrame]),
        );
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Ambiguous { .. }),
            "{kind:?}: {outcome:?}"
        );
        ran_a_job(&witness, "latched");
        // The double notices the dropped stdin on its own task.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !witness.stdin_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{kind:?}: the latched turn dropped the toolhost's stdin"));
        assert_the_turn_end_killed_everything(&witness, &format!("{kind:?} latched"), true);
    }
}

/// **No tool frame reaches the capsule once the turn has ended.** A Code Mode
/// cell calls `exec_command` in a loop; the next model request fails, and
/// nanocode detaches the still-running cell instead of ending it. From the
/// turn's end on, the cell keeps calling, and the gate answers every call
/// without a frame: in the double's own log nothing but kills follows the
/// turn end's `KillAll`.
///
/// The failing answer is held until the double has logged the cell's first
/// `exec`, so the cell has run its loop before the turn ends however long its
/// interpreter process takes to start: the cell yields to the model on its
/// 200 ms wall clock, not on its progress, so an interpreter slower to start
/// than that (a host under load) would otherwise end the turn before any
/// `exec`.
#[tokio::test]
async fn no_tool_frame_reaches_the_capsule_once_the_turn_has_ended() {
    let looping = Gate::default();
    let mut script = vec![code_reply(
        "r1",
        "// @exec: {\"yield_time_ms\": 200}\nfor (;;) { await tools.exec_command({cmd: \"tick\", yield_time_ms: 250}); }",
        usage(1, 0, 1),
    )];
    script.extend(failed_with_reconnects(Reply::Gated(
        looping.clone(),
        Box::new(Reply::Drop),
    )));
    let mock = MockProvider::start(script).await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("loop");
    let (outcome, ()) = tokio::join!(
        turn(session.as_mut(), &prompt),
        bounded("the cell's first exec", async {
            while !witness.kinds().contains(&"exec") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            looping.open();
        })
    );
    assert!(
        matches!(
            outcome,
            TurnOutcome::ProviderFailed {
                class: ProviderFailureClass::Transient,
                ..
            }
        ),
        "{outcome:?}"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let kinds = witness.kinds();
    let turn_end = kinds
        .iter()
        .position(|kind| *kind == "kill_all")
        .unwrap_or_else(|| panic!("the turn's end sent a KillAll: {} frames", kinds.len()));
    assert!(
        kinds[..turn_end].contains(&"exec"),
        "the cell ran its loop before the turn ended"
    );
    let after: Vec<&&str> = kinds[turn_end..]
        .iter()
        .filter(|kind| **kind != "kill_all" && **kind != "signal")
        .collect();
    assert!(after.is_empty(), "frames after the turn ended: {after:?}");
}

/// How long the double stops reading after the first `Stdin` frame in
/// [`no_frame_admitted_before_the_turn_end_follows_its_kill_all`]: long past the
/// cell's 1 s yield, so the turn has ended (its gate closed, its `KillAll`
/// queued) while the write still has frames to send, and well inside the turn
/// end's 5 s wait for the `KillAll`'s `Done`.
const STDIN_PAUSE: Duration = Duration::from_secs(3);

/// **No frame that can change the capsule follows the turn end's `KillAll`,
/// even one a seam call was admitted to send before the gate closed.** A Code
/// Mode cell starts `cat`, left running past a 50 ms yield, and writes 2 MiB
/// to it: one `write_stdin` call, admitted once and sent as 32 `Stdin` frames.
/// The toolhost stops reading after the first, so the rest queue up behind it;
/// the cell yields at 1 s, the next model request fails, and the turn ends
/// while that call still has frames to send. The toolhost reads on
/// [`STDIN_PAUSE`] after it stopped. In the double's own log, nothing that can
/// change the capsule (`exec`, `stdin`, `write_file`, `remove_file`) follows
/// the `KillAll`.
///
/// The failing answer is held until the double has logged the first `Stdin`
/// frame, so the turn ends with the write's frames queued however long the
/// cell's interpreter process takes to start: the cell yields to the model on
/// its 1 s clock, not on its progress, so an interpreter slower to start than
/// that (a host under load) would otherwise end the turn before the write.
///
/// **Would red if:** the gate were read only when a call is admitted, not as
/// each of its frames is queued (watched: `stdin` frames after the
/// `KillAll`).
#[tokio::test]
async fn no_frame_admitted_before_the_turn_end_follows_its_kill_all() {
    let source = r#"// @exec: {"yield_time_ms": 1000}
const cat = await tools.exec_command({"cmd": "cat", "yield_time_ms": 50});
await tools.write_stdin({"session_id": cat.session_id, "chars": "x".repeat(2 * 1024 * 1024), "yield_time_ms": 250});
text("wrote");"#;
    let writing = Gate::default();
    let mut script = vec![code_reply("r1", source, usage(1, 0, 1))];
    script.extend(failed_with_reconnects(Reply::Gated(
        writing.clone(),
        Box::new(Reply::Drop),
    )));
    let mock = MockProvider::start(script).await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Hold],
        pause_after_first_stdin: Some(STDIN_PAUSE),
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let prompt = openai_prompt("write");
    let (outcome, ()) = tokio::join!(
        turn(session.as_mut(), &prompt),
        bounded("the write's first stdin frame", async {
            while !witness.kinds().contains(&"stdin") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            writing.open();
        })
    );
    assert!(
        matches!(
            outcome,
            TurnOutcome::ProviderFailed {
                class: ProviderFailureClass::Transient,
                ..
            }
        ),
        "{outcome:?}"
    );
    let kinds = witness.kinds();
    let turn_end = kinds
        .iter()
        .position(|kind| *kind == "kill_all")
        .unwrap_or_else(|| panic!("the turn's end sent a KillAll: {kinds:?}"));
    assert!(
        kinds[..turn_end].contains(&"stdin"),
        "the write began before the turn ended: {kinds:?}"
    );
    let after: Vec<&&str> = kinds[turn_end..]
        .iter()
        .filter(|kind| matches!(**kind, "exec" | "stdin" | "write_file" | "remove_file"))
        .collect();
    assert!(
        after.is_empty(),
        "{} frame(s) that can change the capsule follow the turn end's KillAll: {after:?}",
        after.len()
    );
}

/// The CPU time, in clock ticks, of every Code Mode interpreter process of this
/// one (`quickjs_threads::interpreters`, read off `/proc`).
fn interpreter_cpu_ticks() -> u64 {
    quickjs_threads::interpreters()
        .into_iter()
        .filter_map(quickjs_threads::process_cpu_ticks)
        .sum()
}

/// **A Code Mode cell still running when the turn fails is ended.** The model
/// starts a cell that spins in JavaScript and yields after 200 ms; the next
/// model request fails 2 s after it arrives, and nanocode DETACHES the turn's
/// cells rather than ending them (its failed-turn path with no tool call in
/// flight). The witness is the kernel's account of the cell's interpreter
/// process: while the model is asked again, it burns CPU (the positive control:
/// a witness that saw no such process could not tell an ended cell from one it
/// never saw), and after `prompt` returns none does, where the detached cell
/// would spin one core.
#[tokio::test]
async fn a_still_running_code_mode_cell_is_ended_at_the_turn_end() {
    let mut script = vec![code_reply(
        "r1",
        "// @exec: {\"yield_time_ms\": 200}\nwhile (true) {}",
        usage(1, 0, 1),
    )];
    script.extend(failed_with_reconnects(Reply::DropAfter(
        Duration::from_secs(2),
    )));
    let mock = MockProvider::start(script).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("spin");
    let (outcome, ()) = tokio::join!(turn(session.as_mut(), &prompt), async {
        mock.wait_for_requests(2).await;
        assert_a_code_mode_cell_runs("before the turn ended").await;
    });
    assert!(
        matches!(
            outcome,
            TurnOutcome::ProviderFailed {
                class: ProviderFailureClass::Transient,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(
        mock.requests().len(),
        2 + RECONNECTS,
        "the cell yielded and the next call failed, as did nanocode's re-sends of it"
    );
    assert_no_code_mode_cell_runs("after the turn ended").await;
}

/// A Code Mode cell that spins in JavaScript and yields after 200 ms, so the
/// model is asked again while it still runs.
fn a_spinning_cell(id: &str) -> Reply {
    code_reply(
        id,
        "// @exec: {\"yield_time_ms\": 200}\nwhile (true) {}",
        usage(1, 0, 1),
    )
}

/// A Code Mode interpreter process of this one burns CPU over the next second:
/// the positive control that keeps [`assert_no_code_mode_cell_runs`] from
/// passing on a process it cannot see.
async fn assert_a_code_mode_cell_runs(path: &str) {
    let before = interpreter_cpu_ticks();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let burned = interpreter_cpu_ticks().saturating_sub(before);
    assert!(
        burned >= 10,
        "{path}: no Code Mode interpreter process of this one burned CPU while its cell \
         spins ({burned} ticks): the witness sees no cell"
    );
}

/// No Code Mode interpreter process of this one burns CPU over the next second.
/// Only meaningful after [`assert_a_code_mode_cell_runs`] saw one burn.
async fn assert_no_code_mode_cell_runs(path: &str) {
    let before = interpreter_cpu_ticks();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let burned = interpreter_cpu_ticks().saturating_sub(before);
    assert!(
        burned < 10,
        "{path}: an interpreter process burned {burned} ticks in the second that followed: the \
         cell still runs"
    );
}

/// Resolve once a second passes in which no Code Mode interpreter process of this one
/// burns CPU: the cell [`assert_a_code_mode_cell_runs`] saw burn has returned.
/// Callers bound it.
async fn wait_until_no_code_mode_cell_runs() {
    loop {
        let before = interpreter_cpu_ticks();
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        if interpreter_cpu_ticks().saturating_sub(before) < 10 {
            return;
        }
    }
}

/// A Code Mode cell that yields at 100 ms, waits 100 ms on a timer, and then
/// runs `tail`, so the model is asked again while the cell runs it.
fn a_cell_that_then(id: &str, tail: &str) -> Reply {
    code_reply(
        id,
        &format!(
            "// @exec: {{\"yield_time_ms\": 100}}\n\
             await new Promise((resolve) => setTimeout(resolve, 100));\n{tail}"
        ),
        usage(1, 0, 1),
    )
}

/// JavaScript that reaches an interrupt check on every iteration.
const A_SPIN: &str = "while (true) {}";

/// Every `CodeModeWorkersLive` count the turn's evidence holds, read off the
/// session's drained record serialized to the JSON the worker publishes for a
/// completed turn, not off the adapter's types. This is the adapter's own
/// record, not a stored copy: the count's path to the main's durable record
/// is pinned through the worker, by
/// `agent_turn_capsule::no_nanocode_cell_outlives_the_shutdown_a_native_step_included`.
fn recorded_live_code_mode_workers(evidence: &kata_types::agent::SessionEvidence) -> Vec<u64> {
    let blob = serde_json::to_vec(evidence).expect("the evidence serializes");
    let blob: Value = serde_json::from_slice(&blob).expect("the blob is JSON");
    blob["events"]
        .as_array()
        .expect("the blob lists its events")
        .iter()
        .filter(|event| event["event"] == "code_mode_workers_live")
        .map(|event| event["live"].as_u64().expect("a count"))
        .collect()
}

/// **A Code Mode cell inside one long native step past a turn's shutdown is
/// recorded live.** kata runs every cell in an interpreter process, and a turn's
/// shutdown kills and reaps its own cells' interpreters before the count is read
/// (the twin below, and the worker's
/// `agent_turn_capsule::no_nanocode_cell_outlives_the_shutdown_a_native_step_included`);
/// the count is process-wide. So a held session's cell, past its 100 ms yield
/// inside one long native sort ([`quickjs_threads::A_LONG_NATIVE_STEP`]) while
/// its next model request stalls, is live when another session's turn ends: a
/// cell that spins, and a next model request that fails 500 ms after it
/// arrives. That turn's record counts at least one live Code Mode worker, and
/// the kernel's account of the held cell's interpreter process, a witness that
/// shares no code with the count, sees it burn CPU after that `prompt`
/// returned.
///
/// **Would red if:** the turn's end recorded no count (watched: no
/// `CodeModeWorkersLive` in the record).
#[tokio::test]
async fn a_code_mode_cell_in_a_native_step_past_the_shutdown_is_recorded_live() {
    let sorting = MockProvider::start(vec![
        a_cell_that_then("r1", quickjs_threads::A_LONG_NATIVE_STEP),
        Reply::Stall,
    ])
    .await;
    let (mut held, _held_witness) = open(&openai(&sorting.url, None), DoubleConfig::default());
    let held_prompt = openai_prompt("sort");
    let held_cancel = CancelToken::new();
    let mut script = vec![a_cell_that_then("r1", A_SPIN)];
    script.extend(failed_with_reconnects(Reply::DropAfter(
        Duration::from_millis(500),
    )));
    let mock = MockProvider::start(script).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("spin");
    let outcome = tokio::select! {
        held_outcome = held.prompt(&held_prompt, &held_cancel) => {
            panic!("the held turn ended with its cell sorting: {held_outcome:?}")
        }
        outcome = async {
            sorting.wait_for_requests(2).await;
            assert_a_code_mode_cell_runs("the held cell's sort").await;
            turn(session.as_mut(), &prompt).await
        } => outcome,
    };
    assert!(
        matches!(
            outcome,
            TurnOutcome::ProviderFailed {
                class: ProviderFailureClass::Transient,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_a_code_mode_cell_runs("after the outcome").await;
    let live = recorded_live_code_mode_workers(&session.take_evidence());
    assert_eq!(live.len(), 1, "one count per turn end: {live:?}");
    assert!(
        live[0] >= 1,
        "the held cell in its native step was live past the shutdown, and the record says \
         {live:?}"
    );
    drop(session.close().await);
    drop(held.close().await);
}

/// **A turn end whose Code Mode cells all reach an interrupt check records no
/// live worker.** The twin of
/// [`a_code_mode_cell_in_a_native_step_past_the_shutdown_is_recorded_live`]:
/// the same spinning turn ([`A_SPIN`]) with no other session's cell live. The
/// shutdown ends its cell, and the record read after it counts `0`; the kernel's
/// account sees the cell burn CPU before the turn ended (the positive control)
/// and no interpreter process burn any after it.
///
/// **Would red if:** the count were read before the shutdown (the spinning
/// cell's worker still live) or counted a worker whose interpreter process had
/// been reaped.
#[tokio::test]
async fn a_turn_end_whose_cells_reach_an_interrupt_check_records_no_live_worker() {
    let mut script = vec![a_cell_that_then("r1", A_SPIN)];
    script.extend(failed_with_reconnects(Reply::DropAfter(
        Duration::from_millis(1_500),
    )));
    let mock = MockProvider::start(script).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("spin");
    let (outcome, ()) = tokio::join!(turn(session.as_mut(), &prompt), async {
        mock.wait_for_requests(2).await;
        assert_a_code_mode_cell_runs("before the turn ended").await;
    });
    assert!(
        matches!(
            outcome,
            TurnOutcome::ProviderFailed {
                class: ProviderFailureClass::Transient,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(
        recorded_live_code_mode_workers(&session.take_evidence()),
        [0],
        "every cell reached an interrupt check, so the shutdown ended it"
    );
    assert_no_code_mode_cell_runs("after the turn ended").await;
    drop(session.close().await);
}

/// **A turn whose future the worker DROPS still has its Code Mode cell ended
/// by `close`.** The worker's deadline race drops `prompt`'s future when
/// nanocode does not confirm a cancel within the worker's own grace, and then
/// calls `close`. Here the model starts a spinning cell and the next model
/// request stalls; the cell is seen spinning, and the future is dropped
/// mid-drive, the agent never having returned its turn. `close` must still shut
/// the agent down: afterwards no interpreter process burns CPU, and the toolhost was
/// sent its `KillAll`.
#[tokio::test]
async fn a_dropped_turn_future_leaves_no_code_mode_cell_after_close() {
    let mock = MockProvider::start(vec![a_spinning_cell("r1"), Reply::Stall]).await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("spin");
    let cancel = CancelToken::new();
    tokio::select! {
        outcome = session.prompt(&prompt, &cancel) => {
            panic!("the stalled turn ended on its own: {outcome:?}")
        }
        () = async {
            mock.wait_for_requests(2).await;
            assert_a_code_mode_cell_runs("before the drop").await;
        } => {}
    }
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert!(close.is_confirmed(), "{close:?}");
    assert!(
        witness.kinds().contains(&"kill_all"),
        "close ran the turn's end: {:?}",
        witness.kinds()
    );
    assert_no_code_mode_cell_runs("dropped mid-drive").await;
}

/// **`close` reports what its own run of a dropped turn's end found.** The
/// worker drops `prompt`'s future past its stop grace, drains the evidence, and
/// only then calls `close`, which runs the turn end the future never reached:
/// what that run records comes after the drain. Here the model's one request
/// starts a cell that runs one long native sort
/// ([`quickjs_threads::A_LONG_NATIVE_STEP`]) inside its 60 s yield, the future
/// is dropped once the kernel's account sees the sort burn CPU, the drained
/// evidence holds no turn-end record, and the toolhost double never answers a
/// `KillAll`. `close`'s report carries `TurnEnd{kill_all, unconfirmed}` (the
/// double's own log holds that one `KillAll`, and its own record the stdin's
/// close) and its live-worker count, `0`: its shutdown killed and reaped the
/// sort's interpreter process before reading it (the kernel lists none of this
/// process's after `close` returned).
///
/// **Would red if:** `close` reported none of its turn end's records (watched:
/// `close` building its report without them).
#[tokio::test]
async fn close_reports_the_turn_end_it_ran_for_a_dropped_future() {
    let mock = MockProvider::start(vec![code_reply(
        "r1",
        &format!(
            "// @exec: {{\"yield_time_ms\": 60000}}\n{}",
            quickjs_threads::A_LONG_NATIVE_STEP
        ),
        usage(1, 0, 1),
    )])
    .await;
    let config = DoubleConfig {
        swallow_kill_all: true,
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let prompt = openai_prompt("sort");
    let cancel = CancelToken::new();
    tokio::select! {
        outcome = session.prompt(&prompt, &cancel) => {
            panic!("the turn ended with its cell sorting: {outcome:?}")
        }
        () = async {
            mock.wait_for_requests(1).await;
            assert_a_code_mode_cell_runs("before the drop").await;
        } => {}
    }
    let turn_end = |event: &kata_types::agent::SessionEvidenceEvent| {
        matches!(
            event,
            kata_types::agent::SessionEvidenceEvent::TurnEnd { .. }
                | kata_types::agent::SessionEvidenceEvent::CodeModeWorkersLive { .. }
        )
    };
    let drained = session.take_evidence();
    assert!(
        !drained.events.iter().any(turn_end),
        "the dropped future never reached its turn end: {:?}",
        drained.events
    );
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert_eq!(
        witness
            .kinds()
            .iter()
            .filter(|kind| **kind == "kill_all")
            .count(),
        1,
        "close ran the turn end's one KillAll: {:?}",
        witness.kinds()
    );
    assert!(
        witness.stdin_closed(),
        "the unconfirmed KillAll dropped the toolhost's stdin"
    );
    assert!(
        quickjs_threads::interpreters().is_empty(),
        "close's shutdown reaped the sort's interpreter: {:?}",
        quickjs_threads::interpreters()
    );
    let reported = close.turn_end();
    assert!(
        reported.iter().any(|event| matches!(
            event,
            kata_types::agent::SessionEvidenceEvent::TurnEnd { step, outcome }
                if step == "kill_all" && outcome == "unconfirmed"
        )),
        "close reports its unconfirmed KillAll: {close:?}"
    );
    assert!(
        reported.iter().any(|event| matches!(
            event,
            kata_types::agent::SessionEvidenceEvent::CodeModeWorkersLive { live: 0 }
        )),
        "close reports its count, the sort's worker reaped: {close:?}"
    );
    assert!(reported.iter().all(turn_end), "{close:?}");
}

/// **A turn end the worker DROPS part-way is finished by `close`.** The turn
/// fails with a spinning cell detached, and its end sends a `KillAll` the
/// toolhost never answers; the cell is seen spinning, and the future is dropped
/// while that `KillAll` waits.
/// `close` re-runs the steps that did not complete: it sends the `KillAll`
/// again, and, that one unconfirmed too, drops the toolhost's stdin so the
/// toolhost kills its processes itself; and the agent is shut down, so no
/// interpreter process burns CPU. The witness is the double's own frame log and
/// its own record of reading EOF.
#[tokio::test]
async fn a_turn_end_dropped_part_way_is_finished_by_close() {
    let mut script = vec![a_spinning_cell("r1")];
    script.extend(failed_with_reconnects(Reply::Drop));
    let mock = MockProvider::start(script).await;
    let config = DoubleConfig {
        swallow_kill_all: true,
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let prompt = openai_prompt("spin");
    let cancel = CancelToken::new();
    let sent_kill_all = async {
        while !witness.kinds().contains(&"kill_all") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        outcome = session.prompt(&prompt, &cancel) => {
            panic!("the turn's end returned past an unanswered KillAll: {outcome:?}")
        }
        () = async {
            sent_kill_all.await;
            assert_a_code_mode_cell_runs("mid-KillAll").await;
        } => {}
    }
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert!(close.is_confirmed(), "{close:?}");
    assert_no_code_mode_cell_runs("dropped mid-KillAll").await;
    let kinds = witness.kinds();
    assert_eq!(
        kinds.iter().filter(|kind| **kind == "kill_all").count(),
        2,
        "close re-ran the KillAll the dropped turn end never saw answered: {kinds:?}"
    );
    assert!(
        witness.stdin_closed(),
        "the unconfirmed KillAll dropped the toolhost's stdin: {:?}",
        witness.kinds()
    );
}

/// The bound a turn's end and a `close` each keep when the toolhost stops
/// reading: the session's `TURN_END_GRACE` and `CLOSE_GRACE` (5 s each), with
/// slack for a loaded host.
const TURN_END_BOUND: Duration = Duration::from_secs(20);

/// A patch adding `path` as one line of `bytes` x's.
fn add_file_patch(path: &str, bytes: usize) -> String {
    format!(
        "*** Begin Patch\n*** Add File: {path}\n+{}\n*** End Patch",
        "x".repeat(bytes)
    )
}

/// **A toolhost gone mid-write cannot hold the turn's end.** A Code Mode cell
/// writes a 2 MiB file and yields while that write is in flight; the next
/// model request fails, and nanocode detaches the cell rather than dropping
/// it, so the write is never given up. The toolhost stops reading its stdin at
/// that frame's header and, a moment later, its stdout ends: a toolhost killed
/// while it reads a large frame. Its stdin stays open, as kata's read-write
/// end of the stdin FIFO keeps it, so the stuck write is never failed. The
/// turn's end must still drop the stdin and return: `prompt` and then `close`
/// each return within [`TURN_END_BOUND`], and `close` confirms the exit.
///
/// The failing answer is held until the double has exited, so the turn ends
/// after the toolhost is gone mid-write: the cell yields to the model on its
/// 2 s clock, not on its progress, and its interpreter process (which carries
/// the 2 MiB source in and the 2 MiB tool input out) can take longer than that
/// to start on a loaded host, which would end the turn before the write began.
///
/// **Would red if:** the writer kept writing past the wire's latch while the
/// turn's end waited on it (watched: `prompt` not returned within 20 s). A
/// turn end that only waits on the writer stays green here: by the time the
/// turn ends, the double's stdout end has latched the wire and the latch has
/// ended the write. `close_stdin`'s abort of a stuck write the latch never
/// ends is refused by the wedged twin,
/// [`a_toolhost_wedged_mid_write_reads_its_stdin_dropped_at_the_turn_end`],
/// and by the toolhost client's `close_stdin_drops_a_stuck_write`.
#[tokio::test]
async fn a_toolhost_gone_mid_write_cannot_hold_the_turn_end() {
    let source = format!(
        "// @exec: {{\"yield_time_ms\": 2000}}\nawait tools.apply_patch({});\ntext(\"written\");",
        Value::from(add_file_patch("/work/big.txt", 2 * 1024 * 1024))
    );
    let gone = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply("r1", &source, usage(1, 0, 1)),
        Reply::Gated(gone.clone(), Box::new(Reply::Drop)),
    ])
    .await;
    let config = DoubleConfig {
        wedge: Some(Wedge {
            body_over: 1024 * 1024,
            then: AfterWedge::Exit,
        }),
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let prompt = openai_prompt("write");
    let cancel = CancelToken::new();
    let (outcome, ()) = tokio::join!(
        tokio::time::timeout(TURN_END_BOUND, session.prompt(&prompt, &cancel)),
        bounded("the double's exit mid-write", async {
            while !witness.has_exited() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            gone.open();
        })
    );
    let outcome = outcome.unwrap_or_else(|_| {
        panic!(
            "prompt did not return within {} s of a toolhost gone mid-write",
            TURN_END_BOUND.as_secs()
        )
    });
    assert!(
        matches!(outcome, TurnOutcome::Ambiguous { .. }),
        "{outcome:?}"
    );
    assert!(
        witness.has_exited() && !witness.kinds().contains(&"write_file"),
        "the double stopped reading at the write's header and exited: {:?}",
        witness.kinds()
    );
    let close = tokio::time::timeout(TURN_END_BOUND, session.close())
        .await
        .unwrap_or_else(|_| panic!("close did not return within {} s", TURN_END_BOUND.as_secs()));
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A toolhost wedged mid-write still reads its stdin end.** As
/// [`a_toolhost_gone_mid_write_cannot_hold_the_turn_end`], a detached Code Mode
/// cell's 2 MiB write is stuck on a toolhost that stopped reading at the
/// frame's header; here the toolhost stays ALIVE, its stdout open, so the wire
/// never latches and nothing but the turn's end can unstick it. The turn end's
/// `KillAll` waits behind the stuck frame unanswered, and once
/// `TURN_END_GRACE` has passed the turn's end drops the toolhost's stdin: by
/// within a second of `prompt`'s return (itself within [`TURN_END_BOUND`]) the
/// double has read its stdin end gone while still running, so its own EOF,
/// not `close`'s `SIGKILL`, is what ends its processes.
///
/// The failing answer is held until the double has stopped reading at the
/// frame's header ([`DoubleWitness::has_wedged`]), so the turn ends with the
/// write stuck: as in its twin, the cell yields to the model on its 2 s clock,
/// not on its progress, and its interpreter process can take longer than that
/// to start on a loaded host, which would end the turn before the write began.
///
/// **Would red if:** `close_stdin` did not abort the writer stuck in that
/// write (watched: `prompt` returned with the double's stdin still held).
#[tokio::test]
async fn a_toolhost_wedged_mid_write_reads_its_stdin_dropped_at_the_turn_end() {
    let source = format!(
        "// @exec: {{\"yield_time_ms\": 2000}}\nawait tools.apply_patch({});\ntext(\"written\");",
        Value::from(add_file_patch("/work/big.txt", 2 * 1024 * 1024))
    );
    let wedged = Gate::default();
    let mut script = vec![code_reply("r1", &source, usage(1, 0, 1))];
    script.extend(failed_with_reconnects(Reply::Gated(
        wedged.clone(),
        Box::new(Reply::Drop),
    )));
    let mock = MockProvider::start(script).await;
    let config = DoubleConfig {
        wedge: Some(Wedge {
            body_over: 1024 * 1024,
            then: AfterWedge::Hang,
        }),
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let prompt = openai_prompt("write");
    let cancel = CancelToken::new();
    let (outcome, ()) = tokio::join!(
        tokio::time::timeout(TURN_END_BOUND, session.prompt(&prompt, &cancel)),
        bounded("the double's wedge mid-write", async {
            while !witness.has_wedged() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            wedged.open();
        })
    );
    let outcome = outcome.unwrap_or_else(|_| {
        panic!(
            "prompt did not return within {} s of a toolhost wedged mid-write",
            TURN_END_BOUND.as_secs()
        )
    });
    assert!(
        matches!(
            outcome,
            TurnOutcome::ProviderFailed {
                class: ProviderFailureClass::Transient,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(
        !witness.has_exited() && !witness.kinds().contains(&"write_file"),
        "the double stopped reading at the write's header and is still running: {:?}",
        witness.kinds()
    );
    // The writer's abort lands on its task a moment after the turn's end
    // asks for it; the double then reads the stdin end gone.
    tokio::time::timeout(Duration::from_secs(1), async {
        while !witness.stdin_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the turn's end dropped the stdin its writer was stuck writing");
    assert!(
        !witness.has_exited(),
        "the double read its stdin end gone alive"
    );
    let close = tokio::time::timeout(TURN_END_BOUND, session.close())
        .await
        .unwrap_or_else(|_| panic!("close did not return within {} s", TURN_END_BOUND.as_secs()));
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A panic unwinding through a turn still ends it.** The worker's task
/// polls `prompt` with no unwind boundary: a panic there drops the turn's
/// future and the session without `close`. Here the model starts a spinning
/// Code Mode cell and the next model request stalls; the cell is seen
/// spinning, and then the task holding the session panics. The double reads
/// EOF on its stdin (the toolhost kills every process it started on it), and
/// once nanocode's shutdown has had its grace no interpreter process burns CPU.
///
/// **Would red if:** the session ended nothing when dropped (watched: the
/// double's stdin left open by the client nanocode's tools still hold).
#[tokio::test]
async fn a_panic_unwinding_through_a_turn_still_ends_it() {
    let mock = MockProvider::start(vec![a_spinning_cell("r1"), Reply::Stall]).await;
    let (session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let (unwind, unwound) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(async move {
        let mut session = session;
        let prompt = openai_prompt("spin");
        let cancel = CancelToken::new();
        tokio::select! {
            outcome = session.prompt(&prompt, &cancel) => {
                panic!("the stalled turn ended on its own: {outcome:?}")
            }
            _ = unwound => panic!("the worker's task unwinds mid-turn"),
        }
    });
    mock.wait_for_requests(2).await;
    assert_a_code_mode_cell_runs("before the panic").await;
    drop(unwind);
    let joined = worker.await.expect_err("the worker's task panicked");
    assert!(joined.is_panic(), "{joined:?}");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !witness.stdin_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the dropped session dropped the toolhost's stdin");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_no_code_mode_cell_runs("after the panic").await;
}

// ── bounded-cleanup ----------------------------------------------------------

/// A toolhost that swallows `Shutdown` (no `Bye`, no exit) is killed after the
/// grace, and the kill's exit is what `close` reports, on either kind.
#[tokio::test]
async fn close_escalates_past_a_swallowed_shutdown() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.answer("r1", "ok")]).await;
        let config = DoubleConfig {
            swallow_shutdown: true,
            ..DoubleConfig::default()
        };
        let (mut session, witness) = open(&kind.adapter(&mock), config);
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{kind:?}: {outcome:?}"
        );
        let close = tokio::time::timeout(Duration::from_secs(30), session.close())
            .await
            .unwrap_or_else(|_| panic!("{kind:?}: close is bounded"));
        assert!(close.is_confirmed(), "{kind:?}: {close:?}");
        assert_eq!(
            witness.signals(),
            [kata_agent::adapter::Signal::Kill],
            "{kind:?}"
        );
        assert!(
            witness.kinds().contains(&"shutdown"),
            "{kind:?}: {:?}",
            witness.kinds()
        );
    }
}

/// How long `close` waits on each of its steps (`CLOSE_GRACE` in
/// `session.rs`): the `Bye`, the exit, the `SIGKILL`'s delivery, and the exit
/// past it.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// A toolhost that swallows `Shutdown` and outlives its `SIGKILL` (a process
/// the kernel cannot reap) leaves `close` with no exit to observe: `close`
/// still returns, within its own bound of [`CLOSE_GRACE`] for the `Bye`, one
/// for the exit and one past the `SIGKILL`, and reports the teardown
/// `Ambiguous`, never `Confirmed`.
///
/// **Would red if:** the wait after the `SIGKILL` were unbounded (watched:
/// `close` never returns and the cell's own timeout fires).
#[tokio::test]
async fn close_is_bounded_past_a_kill_the_toolhost_outlives() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let config = DoubleConfig {
        swallow_shutdown: true,
        on_kill: OnKill::Outlive,
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let started = std::time::Instant::now();
    let close = tokio::time::timeout(CLOSE_GRACE * 3 + Duration::from_secs(5), session.close())
        .await
        .expect("close is bounded past a kill the toolhost outlives");
    assert!(
        started.elapsed() >= CLOSE_GRACE * 3,
        "close waited out each of its three graces: {:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            close.teardown(),
            kata_agent::resource_bounds::TeardownOutcome::Ambiguous {
                reason: kata_agent::resource_bounds::AmbiguousTeardown::Unobservable(_),
                ..
            }
        ),
        "no exit was observed, so the teardown is ambiguous: {close:?}"
    );
    assert_eq!(witness.signals(), [kata_agent::adapter::Signal::Kill]);
    assert!(!witness.has_exited(), "the double outlived its kill");
}

/// A toolhost that swallows `Shutdown` and whose `SIGKILL` delivery never
/// returns (a `youki kill` that hangs) still leaves `close` bounded by its own
/// graces: one for the `Bye`, one for the exit, one for the delivery. The
/// teardown is `Ambiguous` and names the delivery, never `Confirmed`.
///
/// **Would red if:** the `SIGKILL`'s delivery were awaited without a bound
/// (watched: `close` never returns and the cell's own timeout fires).
#[tokio::test]
async fn close_is_bounded_past_a_kill_whose_delivery_never_returns() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let config = DoubleConfig {
        swallow_shutdown: true,
        on_kill: OnKill::Hang,
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let started = std::time::Instant::now();
    let close = tokio::time::timeout(CLOSE_GRACE * 3 + Duration::from_secs(5), session.close())
        .await
        .expect("close is bounded past a kill whose delivery never returns");
    assert!(
        started.elapsed() >= CLOSE_GRACE * 3,
        "close waited out each of its three graces: {:?}",
        started.elapsed()
    );
    match close.teardown() {
        kata_agent::resource_bounds::TeardownOutcome::Ambiguous {
            reason: kata_agent::resource_bounds::AmbiguousTeardown::Unobservable(why),
            ..
        } => assert!(why.contains("delivering"), "{why}"),
        other => panic!("no delivery was observed, so the teardown is ambiguous: {other:?}"),
    }
    assert_eq!(witness.signals(), [kata_agent::adapter::Signal::Kill]);
    assert!(!witness.has_exited(), "the double never exited");
}

// ── refusal-without-fallback --------------------------------------------------

/// The tools a Responses request offers the model, as `type:name`, the
/// namespaces that group them (nanocode 8ec3b215 offers its tools inside one
/// `namespace` tool, `functions`), and the host tools a Code Mode cell may
/// call, as their `### \`name\`` sections in the `exec` tool's description:
/// everything the model can reach, read out of the request body the mock
/// received.
fn codex_model_facing(request: &Value) -> Value {
    assert!(
        request
            .get("tools")
            .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty)),
        "the request carries top-level tools besides the Code Mode set: {}",
        request["tools"]
    );
    let listed: Vec<&Value> = request["input"]
        .as_array()
        .expect("the request carries an input array")
        .iter()
        .filter(|item| item["type"] == "additional_tools")
        .flat_map(|item| item["tools"].as_array().expect("additional_tools.tools"))
        .collect();
    let namespaces: Vec<&str> = listed
        .iter()
        .filter(|tool| tool["type"] == "namespace")
        .map(|tool| tool["name"].as_str().unwrap_or("?"))
        .collect();
    let offered: Vec<&Value> = listed
        .into_iter()
        .flat_map(|tool| {
            if tool["type"] == "namespace" {
                tool["tools"]
                    .as_array()
                    .expect("a namespace lists its tools")
                    .iter()
                    .collect()
            } else {
                vec![tool]
            }
        })
        .collect();
    let direct: Vec<String> = offered
        .iter()
        .map(|tool| {
            format!(
                "{}:{}",
                tool["type"].as_str().unwrap_or("?"),
                tool["name"].as_str().unwrap_or("?")
            )
        })
        .collect();
    json!({
        "namespaces": namespaces,
        "direct": direct,
        "nested": nested_tools(offered.iter().copied()),
    })
}

/// The host tools Code Mode's `exec` declares to the model: the `### \`name\``
/// sections of its description.
fn nested_tools<'a>(offered: impl IntoIterator<Item = &'a Value>) -> Vec<String> {
    let exec = offered
        .into_iter()
        .find(|tool| tool["name"] == "exec")
        .expect("Code Mode's exec tool is offered");
    exec["description"]
        .as_str()
        .expect("exec has a description")
        .lines()
        .filter_map(|line| line.strip_prefix("### `"))
        .filter_map(|rest| rest.strip_suffix('`'))
        .map(str::to_owned)
        .collect()
}

/// Check B: what the model can reach is exactly the pinned set: Code Mode's
/// `exec` and `wait`, and under `exec` the five host tools, with no hosted
/// tool anywhere. Every pinned entry is one of three things: a tool that
/// forwards to the tool host (`apply_patch`, `exec_command`, `write_stdin`,
/// `view_image`), a tool with no effect outside the turn's own state
/// (`update_plan`), or Code Mode (`exec`, `wait`), whose only effects are calls
/// to the first two. Its instructions name `/work`, never the test's own
/// working directory. A nanocode bump that moves the model-facing surface goes
/// red here.
#[tokio::test]
async fn the_model_facing_tool_list_is_the_pinned_set() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let request = &mock.requests()[0];
    let reached = codex_model_facing(request);
    let pinned: Value =
        serde_json::from_str(include_str!("fixtures/codex_model_tools.json")).expect("fixture");
    assert_eq!(reached, pinned, "the model-facing tool set moved");
    let text = request.to_string();
    for hosted in ["web_search", "image_generation"] {
        assert!(
            !text.contains(hosted),
            "a hosted {hosted} tool is model-facing"
        );
    }
    assert!(
        text.contains("<cwd>/work</cwd>"),
        "the instructions must name /work"
    );
    let cwd = std::env::current_dir().expect("cwd");
    assert!(
        !text.contains(cwd.to_str().expect("utf-8 cwd")),
        "the request names the host's working directory"
    );
}

/// **A turn end whose `KillAll` is not confirmed says so in the turn's
/// evidence.** Three turns: a toolhost that answers `KillAll` (the control:
/// no `TurnEnd` record); one that never answers it, so the turn's end drops
/// its stdin after the grace (`TurnEnd{kill_all, unconfirmed}`); and one whose
/// wire breaks mid-turn, so no `KillAll` can be sent and its stdin is dropped
/// at once (`TurnEnd{kill_all, wire_broken}`). The double's own record of
/// reading EOF is the witness the stdin was dropped.
///
/// **Would red if:** the turn's end dropped the toolhost's stdin without a
/// record, which is what the outcome alone cannot say.
#[tokio::test]
async fn an_unconfirmed_turn_end_kill_all_is_recorded_in_the_evidence() {
    let turn_end = |events: &[kata_types::agent::SessionEvidenceEvent]| {
        events
            .iter()
            .filter_map(|event| match event {
                kata_types::agent::SessionEvidenceEvent::TurnEnd { step, outcome } => {
                    Some(format!("{step}:{outcome}"))
                }
                _ => None,
            })
            .collect::<Vec<String>>()
    };
    for (swallow, expected) in [
        (false, vec![]),
        (true, vec!["kill_all:unconfirmed".to_owned()]),
    ] {
        let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
        let config = DoubleConfig {
            swallow_kill_all: swallow,
            ..DoubleConfig::default()
        };
        let (mut session, witness) = open(&openai(&mock.url, None), config);
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            turn_end(&session.take_evidence().events),
            expected,
            "KillAll swallowed: {swallow}"
        );
        assert_eq!(
            witness.stdin_closed(),
            swallow,
            "KillAll swallowed: {swallow}"
        );
        drop(session.close().await);
    }
    let mock = MockProvider::start(vec![exec_command_reply(
        "r1",
        &exec_args("echo gone"),
        usage(1, 0, 1),
    )])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::CloseStdout],
        ..DoubleConfig::default()
    };
    let (mut session, _witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Ambiguous { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        turn_end(&session.take_evidence().events),
        ["kill_all:wire_broken"]
    );
    drop(session.close().await);
}

/// **`exec_command` runs a login shell unless the model says otherwise, as
/// nanocode declares.** The tool's schema tells the model `login` "Defaults to
/// true", and nanocode's own executor runs `-lc` when it is omitted. Three
/// calls: `login` omitted, `true` and `false`; the toolhost double's own log of
/// the `Exec` frames it received reads `login` true, true, false.
///
/// **Would red if:** an omitted `login` ran `sh -c`, which the model was told it
/// would not.
#[tokio::test]
async fn an_exec_command_omitting_login_runs_a_login_shell() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("echo omitted"), usage(1, 0, 1)),
        exec_command_reply(
            "r2",
            &json!({"cmd": "echo login", "yield_time_ms": 30_000, "login": true}),
            usage(1, 0, 1),
        ),
        exec_command_reply(
            "r3",
            &json!({"cmd": "echo plain", "yield_time_ms": 30_000, "login": false}),
            usage(1, 0, 1),
        ),
        message_reply("r4", "ok", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let logins: Vec<(String, bool)> = witness
        .frames()
        .into_iter()
        .filter_map(|frame| match frame {
            WorkerFrame::Exec { script, login, .. } => Some((script, login)),
            _ => None,
        })
        .collect();
    assert_eq!(
        logins,
        [
            ("echo omitted".to_owned(), true),
            ("echo login".to_owned(), true),
            ("echo plain".to_owned(), false),
        ]
    );
}

/// **The model is told where its tools run.** nanocode's codex backend sends
/// fixed permissions instructions that say `sandbox_mode` is
/// `danger-full-access` and "Network access is enabled", false in a kata
/// capsule. The Responses turn's developer message carries kata's
/// `<kata_capsule>` statement right after them: tools run in the capsule at
/// `/work`, offline unless the stage declared network access. Read off the
/// mock provider's own log of the first request.
///
/// **Would red if:** the statement were dropped, or placed before nanocode's
/// permissions instructions it corrects.
#[tokio::test]
async fn the_model_is_told_its_capsule_is_offline_unless_declared() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let text = mock.requests()[0].to_string();
    let at = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("the request carries {needle:?}: {text}"))
    };
    let permissions = at("Network access is enabled");
    let statement = at("<kata_capsule>");
    let offline = at("The capsule has no network access unless this stage declared it");
    assert!(
        permissions < statement && statement < offline,
        "nanocode's permissions, then kata's statement"
    );
    assert!(text.contains("working directory is /work"), "{text}");
}

/// Check C: a scripted turn of each kind over the double with workspace
/// `/work` (which does not exist on this host) reaches the double for every
/// call, and leaves the test process's own fresh working directory empty:
/// nanocode probed nothing on the host. The capsule's `AGENTS.md`, read
/// through the toolhost as the turn's first frame, is what reaches the model.
#[tokio::test]
async fn no_host_probe_without_a_supplied_environment() {
    let cwd = tempfile::tempdir().expect("tempdir");
    std::env::set_current_dir(cwd.path()).expect("enter the empty cwd");
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.run("r1", "ls"), kind.answer("r2", "ok")]).await;
        let config = DoubleConfig {
            files: [("/work/AGENTS.md".to_owned(), b"Use sh.".to_vec())].into(),
            ..DoubleConfig::default()
        };
        let (mut session, witness) = open(&kind.adapter(&mock), config);
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{kind:?}: {outcome:?}"
        );
        assert!(
            matches!(witness.frames().first(), Some(WorkerFrame::ReadFile { path, .. }) if path == "/work/AGENTS.md"),
            "{kind:?}: the project instructions are read inside the capsule: {:?}",
            witness.kinds()
        );
        assert!(
            mock.requests()[0].to_string().contains("Use sh."),
            "{kind:?}: the capsule's AGENTS.md reaches the model"
        );
        assert_eq!(execs(&witness), ["ls @ /work"], "{kind:?}");
    }
    let left: Vec<_> = std::fs::read_dir(cwd.path()).expect("read cwd").collect();
    assert!(
        left.is_empty(),
        "the turns wrote into the host cwd: {left:?}"
    );
}

/// A prompt that names no model is refused by name before any model call:
/// nanocode would otherwise run its own default model, and kata never
/// chooses one.
#[tokio::test]
async fn a_turn_naming_no_model_is_refused_before_any_model_call() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let mut prompt = openai_prompt("go");
    prompt.model_hint = None;
    let outcome = turn(session.as_mut(), &prompt).await;
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("expected Refused, got {outcome:?}");
    };
    assert!(reason.starts_with("agent_model_undeclared"), "{reason}");
    assert!(
        mock.requests().is_empty(),
        "no model call before the refusal"
    );
}

/// An `AGENTS.md` that exists in the capsule but is not text is refused by its
/// own name (`project_instructions_unreadable`), not as a lost toolhost, and
/// before any model call.
#[tokio::test]
async fn an_unreadable_agents_md_is_refused_by_name_before_any_model_call() {
    let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
    let config = DoubleConfig {
        files: [("/work/AGENTS.md".to_owned(), vec![0xff, 0xfe, 0x00])].into(),
        ..DoubleConfig::default()
    };
    let (mut session, _witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("expected Refused, got {outcome:?}");
    };
    assert!(
        reason.starts_with("project_instructions_unreadable"),
        "{reason}"
    );
    assert!(
        mock.requests().is_empty(),
        "no model call before the refusal"
    );
}

/// A toolhost whose `Hello` names another source digest is refused before any
/// model call and before any frame, on either kind.
#[tokio::test]
async fn a_toolhost_with_another_source_digest_is_refused_before_any_model_call() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.answer("r1", "ok")]).await;
        let config = DoubleConfig {
            hello: HelloMode::WrongDigest,
            ..DoubleConfig::default()
        };
        let (mut session, witness) = open(&kind.adapter(&mock), config);
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::Refused { reason } = &outcome else {
            panic!("{kind:?}: expected Refused, got {outcome:?}");
        };
        assert!(
            reason.starts_with("toolhost_mismatch"),
            "{kind:?}: {reason}"
        );
        assert!(
            mock.requests().is_empty(),
            "{kind:?}: a model call before the refusal"
        );
        assert!(
            witness.frames().is_empty(),
            "{kind:?}: no frame before an admitted Hello"
        );
    }
}

/// A toolhost that closes its stdout without a `Hello` is absent.
#[tokio::test]
async fn a_silent_toolhost_is_refused_absent() {
    let mock = MockProvider::start(Vec::new()).await;
    let config = DoubleConfig {
        hello: HelloMode::Silent,
        ..DoubleConfig::default()
    };
    let (mut session, _witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("expected Refused, got {outcome:?}");
    };
    assert!(reason.starts_with("toolhost_absent"), "{reason}");
    assert!(mock.requests().is_empty());
}

/// A prompt with no harness credential, or the other provider's, is refused.
#[tokio::test]
async fn a_prompt_without_a_harness_credential_is_refused() {
    let mock = MockProvider::start(Vec::new()).await;
    for credential in [
        None,
        Some(HarnessCredential::new(HarnessAuth::AnthropicApiKey(
            "sk-ant-mock".to_owned(),
        ))),
        Some(HarnessCredential::new("not a harness auth")),
    ] {
        let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
        let mut prompt = openai_prompt("go");
        prompt.credential = credential;
        let outcome = turn(session.as_mut(), &prompt).await;
        let TurnOutcome::Refused { reason } = &outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert!(reason.starts_with("credential_unavailable"), "{reason}");
    }
    assert!(mock.requests().is_empty());
}

/// One attempt is one turn: a second prompt on a session is refused by name,
/// on either kind, and reaches no provider.
#[tokio::test]
async fn a_second_prompt_on_one_session_is_refused() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.answer("r1", "ok")]).await;
        let (mut session, _witness) = open(&kind.adapter(&mock), DoubleConfig::default());
        let first = turn(session.as_mut(), &kind.prompt("go")).await;
        assert!(
            matches!(first, TurnOutcome::Completed { .. }),
            "{kind:?}: {first:?}"
        );
        let second = turn(session.as_mut(), &kind.prompt("again")).await;
        let TurnOutcome::Refused { reason } = &second else {
            panic!("{kind:?}: expected Refused, got {second:?}");
        };
        assert!(
            reason.starts_with("one_turn_per_session"),
            "{kind:?}: {reason}"
        );
        assert_eq!(mock.requests().len(), 1, "{kind:?}");
    }
}

/// A re-dispatched attempt re-derives the same session id from its seed, a
/// different seed is a different id, and the id the PROVIDER is told (the
/// request's `client_metadata.session_id`, read off the mock's own log) is
/// that id: the version-7 UUID nanocode requires.
#[tokio::test]
async fn the_session_id_is_rederived_from_the_seed() {
    async fn told(seed: u8) -> (String, String) {
        let mock = MockProvider::start(vec![message_reply("r1", "ok", usage(1, 0, 1))]).await;
        let (mut session, _witness) = open_scoped(
            &openai(&mock.url, None),
            DoubleConfig::default(),
            scope_with(seed, 1024),
        );
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{outcome:?}"
        );
        let request = &mock.requests()[0];
        let told = request["client_metadata"]["session_id"]
            .as_str()
            .unwrap_or_else(|| panic!("the request names its session: {request}"))
            .to_owned();
        (told, session.session_id().as_str().to_owned())
    }
    let (first, first_id) = told(3).await;
    let (again, _) = told(3).await;
    let (other, _) = told(4).await;
    assert_eq!(first, again, "one seed, one session id on the wire");
    assert_ne!(first, other, "another seed, another session id on the wire");
    assert_eq!(first, first_id, "the provider is told the session's own id");
    assert_eq!(first.len(), 36, "{first}");
    assert_eq!(&first[14..15], "7", "a version-7 UUID: {first}");
}

/// A model call that reports no usage leaves the turn's usage UNKNOWN, never
/// zero.
///
/// Read from nanocode's `Usage` parsers at 8ec3b215 (every class
/// `#[serde(default)]`; MEASURED at 2ac77424), and the same on the Messages
/// kind: a usage object that is present but omits a class reads that class as
/// 0, since nanocode's parsers default every class. This cell does not claim that case.
#[tokio::test]
async fn a_call_reporting_no_usage_leaves_the_usage_unknown() {
    let mock = MockProvider::start(vec![Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": "r1"}}),
        json!({"type": "response.output_text.delta", "output_index": 0, "delta": "ok"}),
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "type": "message", "id": "msg_r1", "role": "assistant",
                "content": [{"type": "output_text", "text": "ok"}],
            },
        }),
        json!({"type": "response.completed", "response": {"id": "r1", "model": MODEL}}),
    ])])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Completed { usage, .. } = outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(usage, None, "an unreported usage is unknown, not zero");
}

/// The message both mocks refuse a request with: the Anthropic API's own words
/// for an account without credit (N6, 2026-11-04).
const CREDIT_REFUSAL: &str = "Your credit balance is too low to access the Anthropic API. \
     Please go to Plans & Billing to upgrade or purchase credits.";

impl Kind {
    /// A 400 answer refusing the request for credit, in the kind's error shape.
    fn credit_refusal(self) -> Reply {
        match self {
            Self::OpenAi => Reply::Status(
                400,
                json!({"error": {"message": CREDIT_REFUSAL, "type": "invalid_request_error", "param": null, "code": null}}),
            ),
            Self::Anthropic => Reply::Status(
                400,
                json!({"type": "error", "error": {"type": "invalid_request_error", "message": CREDIT_REFUSAL}}),
            ),
        }
    }

    /// A 529 overload, in the kind's error shape.
    fn overloaded(self) -> Reply {
        match self {
            Self::OpenAi => Reply::Status(
                529,
                json!({"error": {"message": "mock overloaded", "type": "server_is_overloaded", "param": null, "code": null}}),
            ),
            Self::Anthropic => Reply::Status(
                529,
                json!({"type": "error", "error": {"type": "overloaded_error", "message": "mock overloaded"}}),
            ),
        }
    }

    /// A 500 server error, in the kind's error shape: transient to both
    /// clients, and not one either waits out (MEASURED at 8ec3b215: a 429,
    /// 502, 503, 504 or 529 each client retries for its patience, up to 600 s,
    /// `nanocode_http::layer::retry::PATIENCE`).
    fn server_error(self) -> Reply {
        match self {
            Self::OpenAi => Reply::Status(
                500,
                json!({"error": {"message": "mock server error", "type": "server_error", "param": null, "code": null}}),
            ),
            Self::Anthropic => Reply::Status(
                500,
                json!({"type": "error", "error": {"type": "api_error", "message": "mock server error"}}),
            ),
        }
    }

    /// The model requests the kind's client sends for one call whose every
    /// attempt fails transiently, MEASURED at 8ec3b215: the Responses client
    /// makes the one attempt kata configures (`RESPONSES_MAX_ATTEMPTS`), then
    /// re-sends the call [`RECONNECTS`] times; the Messages client makes
    /// eleven whatever kata asks (nanocode hard-codes them; five at 2ac77424),
    /// with backoff between them ([`RETRY_EXHAUSTION_BOUND`]).
    const fn transient_attempts(self) -> usize {
        match self {
            Self::OpenAi => 1 + RECONNECTS,
            Self::Anthropic => 11,
        }
    }

    /// The kind's adapter over `mock`, retrying a transient failure as the
    /// kind's client does ([`Self::transient_attempts`]).
    fn retrying_adapter(self, mock: &MockProvider) -> NanocodeAdapter {
        match self {
            Self::OpenAi => NanocodeAdapter::openai().with_endpoint(TestEndpoint {
                url: mock.url.clone(),
                websocket_url: None,
            }),
            Self::Anthropic => anthropic(mock),
        }
    }
}

/// **A provider's refusal of the turn's first request is a known failure, not
/// an ambiguity, on either kind.** The mock answers the one request with a 400
/// refusing it for credit; nanocode does not retry it. The turn ends
/// `ProviderFailed` classed `Refused`, carrying the provider's own error type
/// and message, charged NOTHING (the provider refused before answering, and
/// nothing was retried), and no tool call ran. The mock's own log holds the one
/// request.
///
/// **Would red if:** the adapter classified the failure by the bytes that left
/// rather than by nanocode's typed error (watched, both kinds, with
/// `NanocodeSession::outcome`'s provider-failure arm removed — the earlier
/// classification: `Ambiguous { issued: ModelTokens, .. }`), or a refusal of
/// the one request were charged as unknown (watched, with
/// `Observed::failed_turn_charge`'s `Nothing` arm removed: `Unknown`).
#[tokio::test]
async fn a_provider_refusal_fails_the_turn_with_the_providers_reason() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.credit_refusal()]).await;
        let (mut session, _witness) = open(&kind.adapter(&mock), DoubleConfig::default());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::ProviderFailed {
            class,
            reason,
            charge,
            tool_called,
        } = &outcome
        else {
            panic!("{kind:?}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{kind:?}");
        assert!(
            reason.contains("HTTP 400 invalid_request_error") && reason.contains(CREDIT_REFUSAL),
            "{kind:?}: the provider's own type and message: {reason}"
        );
        assert_eq!(*charge, FailedTurnCharge::Nothing, "{kind:?}");
        assert!(!tool_called, "{kind:?}: no tool ran");
        assert_eq!(
            mock.requests().len(),
            1,
            "{kind:?}: a refusal is not re-sent"
        );
    }
}

/// **A transient failure that outlives the harness's own retries is a known
/// failure classed transient, on either kind.** Every attempt the kind's client
/// makes for the turn's first call is answered 500: nanocode retries it (the
/// mock's own log holds every attempt, [`Kind::transient_attempts`]) and ends
/// the turn on the last, about 180 s in on the Messages kind
/// ([`RETRY_EXHAUSTION_BOUND`]).
/// The outcome is `ProviderFailed` classed `Transient`, naming the provider's
/// answer, and its charge is UNKNOWN, never zero: no call completed, and a
/// transient failure is not proof that nothing billed.
///
/// **Would red if:** the adapter classified the failure by the bytes that left
/// (watched, both kinds, with `NanocodeSession::outcome`'s provider-failure arm
/// removed — the earlier classification: `Ambiguous { issued: ModelTokens, ..
/// }`).
#[tokio::test]
async fn a_transient_failure_past_the_harness_retries_is_classed_transient() {
    for kind in KINDS {
        let attempts = kind.transient_attempts();
        let mut script = vec![kind.server_error(); attempts];
        script.push(kind.answer("r1", "must never be asked for"));
        let mock = MockProvider::start(script).await;
        let (mut session, _witness) = open(&kind.retrying_adapter(&mock), DoubleConfig::default());
        let outcome = exhausting_turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::ProviderFailed {
            class,
            reason,
            charge,
            tool_called,
        } = &outcome
        else {
            panic!("{kind:?}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Transient, "{kind:?}");
        assert!(
            reason.contains("HTTP 500") && reason.contains("mock server error"),
            "{kind:?}: the provider's answer: {reason}"
        );
        assert_eq!(*charge, FailedTurnCharge::Unknown, "{kind:?}");
        assert!(!tool_called, "{kind:?}: no tool ran");
        assert_eq!(
            mock.requests().len(),
            attempts,
            "{kind:?}: the harness retried the call to its last attempt"
        );
    }
}

/// **kata holds nanocode's Responses client to six sends of a failing call
/// (seven on the WebSocket), within seconds.** kata, not the harness, is the
/// retry authority, so the adapter configures the client's fewest attempts (its
/// `RESPONSES_MAX_ATTEMPTS`, one); nanocode then re-sends a call whose stream
/// failed reconnectably [`RECONNECTS`] more times, a count no knob reaches, and
/// on the WebSocket transport (production's) it first falls back to HTTPS once
/// the attempt fails. Every send of the turn's first call fails — answered 500
/// over HTTPS, the socket or connection dropped at once over the WebSocket —
/// and the mock's own log holds exactly `1 + RECONNECTS` requests over HTTPS,
/// `2 + RECONNECTS` over the WebSocket, the turn ending between
/// [`RESPONSES_RETRY_BACKOFF`] (nanocode's 200 ms doubling between re-sends)
/// and [`RESPONSES_RETRY_CEILING`] after it began. MEASURED at 8ec3b215: 6
/// requests in 6.22 s over HTTPS, 7 in 6.22 s over the WebSocket.
///
/// **Would red if:** the adapter left the client's attempts at nanocode's
/// default, five (watched: `configure` without its `max_attempts`).
#[tokio::test]
async fn the_responses_client_sends_a_failing_call_six_times_within_seconds() {
    for websocket in [false, true] {
        let (failed, sends) = if websocket {
            (Reply::Drop, 2 + RECONNECTS)
        } else {
            (Kind::OpenAi.server_error(), 1 + RECONNECTS)
        };
        let mut script = vec![failed; sends];
        script.push(Kind::OpenAi.answer("r1", "must never be asked for"));
        let mock = MockProvider::start(script).await;
        let adapter = openai(&mock.url, websocket.then_some(mock.ws_url.as_str()));
        let (mut session, _witness) = open(&adapter, DoubleConfig::default());
        let started = std::time::Instant::now();
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        let took = started.elapsed();
        let TurnOutcome::ProviderFailed { class, .. } = &outcome else {
            panic!("websocket {websocket}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(
            *class,
            ProviderFailureClass::Transient,
            "websocket {websocket}"
        );
        assert_eq!(
            mock.requests().len(),
            sends,
            "websocket {websocket}: kata's one attempt and nanocode's re-sends of it, no more"
        );
        assert!(
            (RESPONSES_RETRY_BACKOFF..RESPONSES_RETRY_CEILING).contains(&took),
            "websocket {websocket}: the turn ended {took:?} after it began"
        );
    }
}

/// nanocode's backoff between its [`RECONNECTS`] re-sends of a Responses call:
/// 200, 400, 800, 1,600 and 3,200 ms.
const RESPONSES_RETRY_BACKOFF: Duration = Duration::from_millis(6_200);

/// What a Responses call kata's adapter configures may take to fail past
/// nanocode's re-sends, the mock answering each at once: the 2ac77424 client's
/// backoff before its fifth attempt (1, 2, 4 and 8 s, each at most 10% over),
/// the most the harness retried a call before kata configured it.
const RESPONSES_RETRY_CEILING: Duration = Duration::from_millis(16_500);

/// **A provider failure after a tool call says a tool ran, and keeps what
/// kata metered.** The first call's Code Mode cell runs `true` in the capsule
/// and completes with its usage; the provider then refuses the second request.
/// The outcome is `ProviderFailed` classed `Refused` with `tool_called` set,
/// read beside the toolhost double's own log of the `Exec`, and charged the
/// first call's usage: the refused request added nothing.
///
/// **Would red if:** the gate's tool-call record were dropped (watched, with
/// `TurnGate::mark_while_open`'s `tool_called` line removed: `tool_called:
/// false`), or the adapter's provider-failure arm (watched: `Ambiguous`).
#[tokio::test]
async fn a_provider_failure_after_a_tool_call_says_a_tool_ran() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.run("r1", "true"), kind.credit_refusal()]).await;
        let (mut session, witness) = open(&kind.adapter(&mock), DoubleConfig::default());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::ProviderFailed {
            class,
            charge,
            tool_called,
            ..
        } = &outcome
        else {
            panic!("{kind:?}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{kind:?}");
        assert!(*tool_called, "{kind:?}: the cell's exec ran");
        assert_eq!(execs(&witness), ["true @ /work"], "{kind:?}");
        let first_call = match kind {
            Kind::OpenAi => TokenUsage {
                input: 1,
                output: 1,
                cache_read: 0,
                cache_write: 0,
            },
            Kind::Anthropic => TokenUsage {
                input: 10,
                output: 3,
                cache_read: 0,
                cache_write: 0,
            },
        };
        assert_eq!(*charge, FailedTurnCharge::Metered(first_call), "{kind:?}");
        assert_eq!(mock.requests().len(), 2, "{kind:?}");
    }
}

/// **A Responses WebSocket `error` event carrying a 4xx HTTP status the harness
/// does not retry is the provider's refusal, as its HTTPS twin is.** The
/// production Responses transport is the WebSocket, where the provider answers a
/// request it refuses with an `error` event stating the HTTP status, not with an
/// HTTP response. The mock answers the turn's request over the WebSocket with
/// such an event, and every re-send of it with the same event: a 400 refusing it
/// for credit, and a 429 `insufficient_quota` (a code nanocode reads as
/// terminal). Each ends `ProviderFailed` classed `Refused`, naming the status
/// and the provider's error type and message, no tool run. MEASURED at
/// 8ec3b215: nanocode re-sends a request an `error` event refused unless the
/// event names a terminal code, [`RECONNECTS`] times on a new socket (its
/// `reconnectable` reads every non-terminal error event so), so the 400 row's
/// mock log holds the request and its re-sends and its charge is UNKNOWN (a
/// re-sent request is no proof nothing billed), while the terminal 429 row
/// holds the one request, charged NOTHING. The refused set, pinned beside them:
/// an `error` event that states no status (re-sent the same way), and a
/// `response.failed` event (terminal, sent once), stay `Ambiguous{ModelTokens}`.
///
/// **Would red if:** the adapter read only HTTP rejections as refusals (it did
/// when the WebSocket's error event went unread: every row
/// `Ambiguous{ModelTokens}`), or read every `error` event as one (watched, with
/// `websocket_error_status` reading a missing `status` as 400: the status-less
/// row `Refused`).
#[tokio::test]
async fn a_websocket_error_event_with_a_4xx_status_is_the_providers_refusal() {
    let credit = json!({"type": "invalid_request_error", "code": null, "message": CREDIT_REFUSAL, "param": null});
    let quota = json!({
        "type": "insufficient_quota", "code": "insufficient_quota", "param": null,
        "message": "You exceeded your current quota, please check your plan and billing details.",
    });
    for (label, event, refused_as, requests) in [
        (
            "a 400 for credit",
            json!({"type": "error", "status": 400, "error": credit}),
            Some((
                format!("HTTP 400 invalid_request_error: {CREDIT_REFUSAL}"),
                FailedTurnCharge::Unknown,
            )),
            1 + RECONNECTS,
        ),
        (
            "a 429 insufficient_quota",
            json!({"type": "error", "status": 429, "error": quota}),
            Some((
                "HTTP 429 insufficient_quota (insufficient_quota): You exceeded your current quota"
                    .to_owned(),
                FailedTurnCharge::Nothing,
            )),
            1,
        ),
        (
            "an error event stating no status",
            json!({"type": "error", "error": credit}),
            None,
            1 + RECONNECTS,
        ),
        (
            "a response.failed event",
            json!({"type": "response.failed", "response": {"id": "r1", "error": quota}}),
            None,
            1,
        ),
    ] {
        let mock = MockProvider::start(vec![Reply::Events(vec![event]); 1 + RECONNECTS]).await;
        let (mut session, _witness) = open(
            &openai(&mock.url, Some(&mock.ws_url)),
            DoubleConfig::default(),
        );
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        assert_eq!(
            mock.requests().len(),
            requests,
            "{label}: the request and nanocode's re-sends of it"
        );
        let Some((refused_as, charged)) = refused_as else {
            assert!(
                matches!(
                    outcome,
                    TurnOutcome::Ambiguous {
                        issued: MayHaveIssued::ModelTokens,
                        ..
                    }
                ),
                "{label}: stays ambiguous: {outcome:?}"
            );
            continue;
        };
        let TurnOutcome::ProviderFailed {
            class,
            reason,
            charge,
            tool_called,
        } = &outcome
        else {
            panic!("{label}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{label}");
        assert!(reason.contains(&refused_as), "{label}: {reason}");
        assert_eq!(*charge, charged, "{label}");
        assert!(!tool_called, "{label}");
    }
}

/// **A ChatGPT plan's usage limit is the provider's refusal, naming the quota, on
/// both Responses transports.** The plan's quota answer (`error.type =
/// "usage_limit_reached"`) is no blip a re-run outlasts: the limit resets on the
/// plan's schedule, hours off. nanocode reads no such code, so over HTTPS its 429
/// is retryable to nanocode, and on the WebSocket an `error` event may state no
/// status at all. The mock answers the turn's request with it three ways — an
/// HTTPS 429, a WebSocket `error` event stating 429, one stating none — and each
/// ends `ProviderFailed` classed `Refused`, its reason naming the usage quota and
/// the provider's code. MEASURED at 8ec3b215: nanocode waits out a 429 for as
/// long as its patience allows (600 s, `nanocode_http::layer::retry::PATIENCE`,
/// whatever the endpoint's `max_attempts`) unless the answer's `retry-after`
/// already passes it, so the mock's 429 states `retry-after: 3600` (the body's
/// `resets_in_seconds`; no real provider's 429 has been measured) and is sent
/// once, charged NOTHING; each WebSocket event is re-sent [`RECONNECTS`] times on a
/// new socket (nanocode's `reconnectable` reads every non-terminal error event
/// so), the mock answering each re-send the same, and charged UNKNOWN (a
/// re-sent request is no proof nothing billed).
///
/// **Would red if:** the adapter classed the answer by nanocode's retry advice
/// alone (watched, before `provider_failure` read the code by name: the HTTPS
/// row `Transient`).
#[tokio::test]
async fn a_plan_usage_limit_is_refused_on_both_transports_naming_the_quota() {
    let limit = json!({
        "type": "usage_limit_reached", "plan_type": "plus", "resets_in_seconds": 3600,
        "message": "The usage limit has been reached",
    });
    for (label, reply, websocket, requests, charged) in [
        (
            "an HTTPS 429",
            Reply::StatusWith(
                429,
                vec![("retry-after", "3600".to_owned())],
                json!({"error": limit}),
            ),
            false,
            1,
            FailedTurnCharge::Nothing,
        ),
        (
            "a WebSocket error event stating 429",
            Reply::Events(vec![
                json!({"type": "error", "status": 429, "error": limit}),
            ]),
            true,
            1 + RECONNECTS,
            FailedTurnCharge::Unknown,
        ),
        (
            "a WebSocket error event stating no status",
            Reply::Events(vec![json!({"type": "error", "error": limit})]),
            true,
            1 + RECONNECTS,
            FailedTurnCharge::Unknown,
        ),
    ] {
        let mock = MockProvider::start(vec![reply; 1 + RECONNECTS]).await;
        let adapter = openai(&mock.url, websocket.then_some(mock.ws_url.as_str()));
        let (mut session, _witness) = open(&adapter, DoubleConfig::default());
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        assert_eq!(
            mock.requests().len(),
            requests,
            "{label}: the request and nanocode's re-sends of it"
        );
        let TurnOutcome::ProviderFailed {
            class,
            reason,
            charge,
            tool_called,
        } = &outcome
        else {
            panic!("{label}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{label}: {reason}");
        assert!(
            reason.contains("usage quota")
                && reason.contains("usage_limit_reached")
                && reason.contains("The usage limit has been reached"),
            "{label}: the reason names the quota and the provider's answer: {reason}"
        );
        assert_eq!(*charge, charged, "{label}");
        assert!(!tool_called, "{label}");
    }
}

/// **A ChatGPT plan's usage limit carried by a `response.failed` event is the
/// provider's refusal too, naming the quota, on both Responses transports.** A
/// stream event that fails the response carries the provider's error object in
/// `response.error`, not at the top level, and nanocode reads every such event
/// it does not know as terminal as retryable. The mock answers every request
/// with that event, over the WebSocket and over HTTPS SSE; each turn ends
/// `ProviderFailed` classed `Refused`, its reason naming the usage quota and the
/// provider's code, whatever nanocode's own retries sent (the mock's log holds
/// at least the one request).
///
/// **Would red if:** the adapter read the code only out of an HTTP error body or
/// a WebSocket `error` event (watched: both rows `Transient`, reason "Responses
/// API returned an error event").
#[tokio::test]
async fn a_plan_usage_limit_in_a_response_failed_event_is_refused_naming_the_quota() {
    let limit = json!({
        "type": "usage_limit_reached", "code": "usage_limit_reached",
        "message": "The usage limit has been reached",
    });
    for (label, websocket) in [("the WebSocket", true), ("HTTPS SSE", false)] {
        let mock = MockProvider::start(
            (0..8)
                .map(|_| {
                    Reply::Events(vec![json!({
                        "type": "response.failed",
                        "response": {"id": "resp_1", "error": limit},
                    })])
                })
                .collect(),
        )
        .await;
        let adapter = openai(&mock.url, websocket.then_some(mock.ws_url.as_str()));
        let (mut session, _witness) = open(&adapter, DoubleConfig::default());
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        assert!(!mock.requests().is_empty(), "{label}: the request was sent");
        let TurnOutcome::ProviderFailed {
            class,
            reason,
            tool_called,
            ..
        } = &outcome
        else {
            panic!("{label}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{label}: {reason}");
        assert!(
            reason.contains("usage quota")
                && reason.contains("usage_limit_reached")
                && reason.contains("The usage limit has been reached"),
            "{label}: the reason names the quota and the provider's answer: {reason}"
        );
        assert!(!tool_called, "{label}");
    }
}

/// **A `previous_response_not_found` answer is a transient failure, on both
/// Responses transports.** The provider refuses a request chained to a stored
/// response it no longer holds; a fresh attempt starts a fresh conversation that
/// chains to none, so the answer is no refusal of the agent. The mock answers
/// the turn's request with the 400 the Responses API sends for it, over HTTPS
/// and as a WebSocket `error` event stating 400: each ends `ProviderFailed`
/// classed `Transient`, naming the provider's code. The mock's own log holds
/// the one HTTPS request, and the WebSocket request with its [`RECONNECTS`]
/// re-sends (MEASURED at 8ec3b215: nanocode re-sends a request a non-terminal
/// error event refused on a new socket; the mock answers each the same).
///
/// **Would red if:** the adapter read every non-retryable 4xx as a refusal
/// (watched, before `provider_failure` read the code by name: the HTTPS row
/// `Refused`).
#[tokio::test]
async fn a_previous_response_not_found_is_transient_on_both_transports() {
    let gone = json!({
        "type": "invalid_request_error", "code": "previous_response_not_found",
        "param": "previous_response_id", "message": "Previous response with id 'resp_1' not found.",
    });
    for (label, reply, websocket, requests) in [
        (
            "an HTTPS 400",
            Reply::Status(400, json!({"error": gone})),
            false,
            1,
        ),
        (
            "a WebSocket error event stating 400",
            Reply::Events(vec![json!({"type": "error", "status": 400, "error": gone})]),
            true,
            1 + RECONNECTS,
        ),
    ] {
        let mock = MockProvider::start(vec![reply; 1 + RECONNECTS]).await;
        let adapter = openai(&mock.url, websocket.then_some(mock.ws_url.as_str()));
        let (mut session, _witness) = open(&adapter, DoubleConfig::default());
        let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
        assert_eq!(
            mock.requests().len(),
            requests,
            "{label}: the request and nanocode's re-sends of it"
        );
        let TurnOutcome::ProviderFailed { class, reason, .. } = &outcome else {
            panic!("{label}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Transient, "{label}: {reason}");
        assert!(
            reason.contains("previous_response_not_found"),
            "{label}: the reason names the provider's code: {reason}"
        );
    }
}

/// **A refusal is charged NOTHING only when it refused the turn's one request,
/// sent once; after a retried attempt it is charged UNKNOWN, on either kind.**
/// The turn's first request is answered 529 overloaded, which the kind's client
/// retries, and the retry 400 refusing it for credit: the turn ends
/// `ProviderFailed` classed `Refused`, and its charge is `Unknown`, never zero,
/// since the overloaded attempt is no proof nothing billed. The mock's own log
/// holds both requests.
///
/// **Would red if:** the `Nothing` charge ignored the retried attempt (watched,
/// with `Observed::failed_turn_charge`'s `attempts_retried == 0` test removed:
/// `Nothing`).
#[tokio::test]
async fn a_refusal_after_a_retried_attempt_is_charged_unknown() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![kind.overloaded(), kind.credit_refusal()]).await;
        let (mut session, _witness) = open(&kind.retrying_adapter(&mock), DoubleConfig::default());
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::ProviderFailed { class, charge, .. } = &outcome else {
            panic!("{kind:?}: expected ProviderFailed, got {outcome:?}");
        };
        assert_eq!(*class, ProviderFailureClass::Refused, "{kind:?}");
        assert_eq!(*charge, FailedTurnCharge::Unknown, "{kind:?}");
        assert_eq!(
            mock.requests().len(),
            2,
            "{kind:?}: the attempt and its retry"
        );
    }
}

/// **A refusal after a model call that COMPLETED is charged UNKNOWN when that
/// call reported no usage.** On the Responses kind the turn's first call runs a
/// Code Mode cell and completes stating no usage; the provider then refuses the
/// second request with a 400. The turn ends `ProviderFailed` classed `Refused`,
/// and its charge is `Unknown`: the completed call billed what kata never saw.
/// (The Messages client fails a call that states no usage, so the Anthropic
/// kind has no such call: `an_anthropic_call_stating_no_usage_is_never_metered`.)
///
/// **Would red if:** the `Nothing` charge ignored the completed call (watched,
/// with `Observed::failed_turn_charge`'s `calls_completed == 0` test removed:
/// `Nothing`).
#[tokio::test]
async fn a_refusal_after_a_call_that_reported_no_usage_is_charged_unknown() {
    let mock = MockProvider::start(vec![
        exec_command_reply("r1", &exec_args("true"), Value::Null),
        Kind::OpenAi.credit_refusal(),
    ])
    .await;
    let (mut session, witness) = open(&Kind::OpenAi.adapter(&mock), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::ProviderFailed { class, charge, .. } = &outcome else {
        panic!("expected ProviderFailed, got {outcome:?}");
    };
    assert_eq!(*class, ProviderFailureClass::Refused);
    assert_eq!(*charge, FailedTurnCharge::Unknown);
    assert_eq!(
        execs(&witness),
        ["true @ /work"],
        "the first call's cell ran"
    );
    assert_eq!(mock.requests().len(), 2);
}

/// **A 5xx the harness does not retry is no refusal: it stays ambiguous.** The
/// Responses kind's one request is answered 500 with a body naming
/// `insufficient_quota`, a code nanocode treats as terminal, so nanocode does
/// not retry it; the provider's answer is a server error, not a 4xx refusal,
/// and the turn ends `Ambiguous{ModelTokens}`. The mock's own log holds the one
/// request.
///
/// **Would red if:** every non-retryable answer were read as a refusal
/// (watched, with `provider_failure`'s 4xx bound removed: `ProviderFailed`
/// classed `Refused`).
#[tokio::test]
async fn a_server_error_the_harness_does_not_retry_stays_ambiguous() {
    let mock = MockProvider::start(vec![Reply::Status(
        500,
        json!({"error": {"type": "insufficient_quota", "code": "insufficient_quota", "param": null, "message": "mock: terminal server answer"}}),
    )])
    .await;
    let (mut session, _witness) = open(&Kind::OpenAi.adapter(&mock), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(
            outcome,
            TurnOutcome::Ambiguous {
                issued: MayHaveIssued::ModelTokens,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(mock.requests().len(), 1, "not retried");
}

/// A toolhost frame the codec refuses latches the wire, and the outcome names
/// the refusal, on either kind; no model call follows the latch.
#[tokio::test]
async fn a_toolhost_frame_the_codec_refuses_is_named_in_the_outcome() {
    for kind in KINDS {
        let mock = MockProvider::start(vec![
            kind.run("r1", "true"),
            kind.answer("r2", "must never be asked for"),
        ])
        .await;
        let config = DoubleConfig {
            execs: vec![ExecMode::Garbage],
            ..DoubleConfig::default()
        };
        let (mut session, _witness) = open(&kind.adapter(&mock), config);
        let outcome = turn(session.as_mut(), &kind.prompt("go")).await;
        let TurnOutcome::Ambiguous { evidence, .. } = &outcome else {
            panic!("{kind:?}: expected Ambiguous, got {outcome:?}");
        };
        assert!(
            evidence.starts_with("toolhost_lost"),
            "{kind:?}: {evidence}"
        );
        assert!(
            evidence.contains("JSON") || evidence.contains("json"),
            "{kind:?}: {evidence}"
        );
        assert_eq!(
            mock.requests().len(),
            1,
            "{kind:?}: no model call follows the latch"
        );
    }
}

/// **A tool call too large to send is refused to the model, not a lost
/// toolhost.** A Code Mode cell runs `exec_command` with a 9 MiB script, past
/// the wire's 8 MiB frame bound, so its frame cannot be encoded and nothing is
/// sent. The model is told so as the call's own failure, the turn goes on and
/// completes, and the double's log holds no `exec`: the outcome is not the
/// latched `toolhost_lost` an unsent frame would otherwise claim.
///
/// **Would red if:** a frame that does not encode latched the wire (watched:
/// `Ambiguous` with evidence "encoding a worker frame failed").
#[tokio::test]
async fn a_tool_call_too_large_to_send_is_refused_to_the_model() {
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "const ran = await tools.exec_command({\"cmd\": \"x\".repeat(9 * 1024 * 1024)});\ntext(JSON.stringify(ran).slice(0, 600));",
            usage(1, 0, 1),
        ),
        message_reply("r2", "ok", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert!(
        execs(&witness).is_empty(),
        "an exec reached the toolhost: {:?}",
        witness.kinds()
    );
    let told = mock_provider::call_output(&mock.requests()[1], "call_r1")
        .expect("the cell's result reached the model");
    assert!(
        told.contains("does not encode"),
        "the model is told the call was not sent: {told}"
    );
}

/// **An `Error` with a null id that names a session is a protocol break.**
/// `kata-toolhost` answers a `Stdin` its session's full queue cannot take with
/// `Error{id: null}` naming the session, the bytes dropped
/// (`kata_toolhost_protocol::ToolhostFrame::Error`), and the protocol says the
/// worker treats it as a break: the model would otherwise read a write that
/// never reached the process as delivered. A Code Mode cell starts `cat`, left
/// running past its yield, then writes to it; the double answers that `Stdin`
/// so. The client latches: the turn is ambiguous and names the refusal, the
/// model's next request never reaches the provider (the mock's own log), and in
/// the double's own log nothing follows the `Stdin` — the latched turn ends by
/// dropping the toolhost's stdin, never by another frame.
///
/// **Would red if:** the client routed a null-id `Error` as anything but a
/// break (the turn would complete on the mock's second reply).
#[tokio::test]
async fn a_null_id_error_naming_a_session_breaks_the_wire() {
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "const started = await tools.exec_command({\"cmd\": \"cat\", \"yield_time_ms\": 250});\n\
             const wrote = await tools.write_stdin({\"session_id\": started.session_id, \"chars\": \"hello\\n\", \"yield_time_ms\": 250});\n\
             text(JSON.stringify(wrote));",
            usage(1, 0, 1),
        ),
        message_reply("r2", "must never be asked for", usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Hold],
        refuse_stdin: true,
        ..DoubleConfig::default()
    };
    let (mut session, witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    let TurnOutcome::Ambiguous { evidence, .. } = &outcome else {
        panic!("expected Ambiguous, got {outcome:?}");
    };
    assert!(evidence.starts_with("toolhost_lost"), "{evidence}");
    assert!(
        evidence.contains("session 1") && evidence.contains("stdin refused"),
        "the outcome names the refused Stdin: {evidence}"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !witness.stdin_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the latched turn dropped the toolhost's stdin");
    assert_eq!(
        witness.kinds(),
        ["read_file", "exec", "stdin"],
        "nothing may follow the Stdin the toolhost refused"
    );
    assert_eq!(mock.requests().len(), 1, "no model call follows the break");
}

/// A scope the harness cannot serve (no `/work` mapping) is refused at
/// `open`, before any frame or model call, on either kind.
#[tokio::test]
async fn a_scope_without_work_is_refused_at_open() {
    for kind in KINDS {
        let artifact = ArtifactRef::new(
            object_id_for_canonical_bytes(b"{\"tree\":\"out\"}"),
            4_096,
            ArtifactPrivacy::Public,
        )
        .id();
        let scope = AttemptScope::new(
            Ulid::new(),
            SessionSeed::new(ContentHash::new([5; 32])),
            vec![GuestMapping {
                artifact,
                guest_path: GuestPath::new("/out").expect("/out"),
                access: GuestAccess::ReadWrite,
            }],
            scope().budgets(),
            CapsuleId(ContentHash::new([9; 32])),
            kata_types::redaction::LiftedSecrets::none(),
        );
        let (process, witness) = toolhost_double::start(DoubleConfig::default());
        let Err(refusal) = kind.unpointed().open(scope, process) else {
            panic!("{kind:?}: a scope without /work must be refused");
        };
        assert!(refusal.to_string().contains("/work"), "{kind:?}: {refusal}");
        assert!(witness.frames().is_empty(), "{kind:?}: no frame was sent");
    }
}

/// The per-session output buffer is bounded (D1 §2.8): a session that writes
/// 3 MiB of stdout is handed to the tool as at most the 1 MiB head+tail window
/// and the count of what fell out between. The Code Mode cell measures the
/// `exec_command` result it was given and reports it as its text, which the
/// mock reads back from the next request. nanocode cuts the text it hands the
/// model further, to its own tool-output budget (MEASURED at 8ec3b215: about
/// 40 KB for this model whatever `max_output_tokens` asks, keeping the head
/// and tail), which drops the window's marker from the middle; its result's
/// `original_token_count` is its count of the text the session handed it, a
/// token per four bytes, so that count, bounded by the window and its marker,
/// is the window read through nanocode.
#[tokio::test]
async fn a_flooding_session_reaches_the_tool_as_its_bounded_window() {
    let source = format!(
        "const result = await tools.exec_command({});\n\
         text(JSON.stringify({{length: result.output.length, \
         original: result.original_token_count}}));",
        json!({"cmd": "yes", "yield_time_ms": 30_000, "max_output_tokens": 4_000_000}),
    );
    let mock = MockProvider::start(vec![
        code_reply("r1", &source, usage(1, 0, 1)),
        message_reply("r2", "ok", usage(1, 0, 1)),
    ])
    .await;
    let config = DoubleConfig {
        execs: vec![ExecMode::Flood(3 * 1024 * 1024)],
        ..DoubleConfig::default()
    };
    let (mut session, _witness) = open(&openai(&mock.url, None), config);
    let outcome = turn(session.as_mut(), &openai_prompt("go")).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    let second = mock.requests()[1].to_string();
    let reported = second
        .split("{\\\"length\\\":")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .and_then(|length| length.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("the cell reported its result: {second}"));
    assert!(
        reported <= 1024 * 1024 + 64,
        "the tool was handed {reported} bytes of a 3 MiB session"
    );
    let original = second
        .split("\\\"original\\\":")
        .nth(1)
        .and_then(|rest| rest.split(['}', ',']).next())
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("the cell reported nanocode's count: {second}"));
    assert!(
        original * 4 <= 1024 * 1024 + 64 + 3,
        "nanocode was handed {original} tokens of a 3 MiB session, past the 1 MiB window"
    );
    assert!(
        original * 4 >= 1024 * 1024,
        "nanocode was handed {original} tokens, less than the full 1 MiB window"
    );
}

/// The inner half of the host-state cell: one turn of `kind` that runs a
/// command and writes a file in the capsule, in a process whose `HOME` and
/// `NANOCODE_HOME` the outer half pointed at fresh directories.
async fn a_turn_that_runs_and_writes(kind: &str) {
    let added = "/work/added.txt";
    let (mock, adapter, prompt) = match kind {
        "openai" => {
            let patch = "*** Begin Patch\n*** Add File: /work/added.txt\n+added\n*** End Patch";
            let source = format!(
                "await tools.exec_command({{cmd: \"ls\"}});\nconst result = await tools.apply_patch({});\ntext(String(result));",
                Value::from(patch)
            );
            let mock = MockProvider::start(vec![
                code_reply("r1", &source, usage(1, 0, 1)),
                message_reply("r2", "ok", usage(1, 0, 1)),
            ])
            .await;
            let adapter = openai(&mock.url, None);
            (mock, adapter, openai_prompt("go"))
        }
        "anthropic" => {
            let mock = MockProvider::start(vec![
                claude_code_reply(
                    "r1",
                    "await tools.Bash({command: \"ls\"});\nconst result = await tools.Write({file_path: \"/work/added.txt\", content: \"added\\n\"});\ntext(JSON.stringify(result));",
                ),
                claude_text_reply("ok"),
            ])
            .await;
            let adapter = anthropic(&mock);
            (mock, adapter, anthropic_prompt("go"))
        }
        other => panic!("no kind `{other}`"),
    };
    let (mut session, witness) = open(&adapter, DoubleConfig::default());
    let outcome = turn(session.as_mut(), &prompt).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{kind}: {outcome:?}"
    );
    assert_eq!(mock.requests().len(), 2, "{kind}: the tool call ran");
    assert_eq!(execs(&witness), ["ls @ /work"], "{kind}");
    assert_eq!(witness.file(added).as_deref(), Some("added\n"), "{kind}");
    drop(session.close().await);
}

/// No host state, on either kind: nanocode's home and the account's home stay
/// EMPTY after a turn that ran a command and wrote a file. For each kind the
/// cell re-executes this test binary with `HOME` and `NANOCODE_HOME` pointed
/// at fresh directories and the `XDG_*` overrides removed (so every per-user
/// default derives from `HOME`), runs the turn there, and then reads both
/// directories itself.
#[tokio::test]
async fn a_turn_writes_nothing_under_home_or_nanocode_home() {
    const INNER: &str = "KATA_NANOCODE_HOME_CELL_INNER";
    if let Some(kind) = std::env::var_os(INNER) {
        a_turn_that_runs_and_writes(&kind.to_string_lossy()).await;
        return;
    }
    for kind in ["openai", "anthropic"] {
        let home = tempfile::tempdir().expect("home");
        let nanocode_home = tempfile::tempdir().expect("nanocode home");
        let mut child = std::process::Command::new(std::env::current_exe().expect("this binary"));
        child
            .args([
                "--exact",
                "a_turn_writes_nothing_under_home_or_nanocode_home",
                "--nocapture",
            ])
            .env(INNER, kind)
            .env("HOME", home.path())
            .env("NANOCODE_HOME", nanocode_home.path());
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("XDG_") {
                child.env_remove(name);
            }
        }
        let output = child.output().expect("the inner turn runs");
        assert!(
            output.status.success(),
            "{kind}: the inner turn failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{kind}: the inner run ran the turn: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        for (name, dir) in [
            ("HOME", home.path()),
            ("NANOCODE_HOME", nanocode_home.path()),
        ] {
            let left: Vec<_> = std::fs::read_dir(dir).expect("read").collect();
            assert!(
                left.is_empty(),
                "{kind}: the turn wrote under {name}: {left:?}"
            );
        }
    }
}

/// Check B for the Anthropic kind: the Messages request's tool list is the
/// pinned set.
#[tokio::test]
async fn the_claude_model_facing_tool_list_is_the_pinned_set() {
    let mock = MockProvider::start(vec![claude_text_reply("ok")]).await;
    let adapter = NanocodeAdapter::anthropic().with_endpoint(TestEndpoint {
        url: format!("{}/messages", mock.url),
        websocket_url: None,
    });
    let (mut session, _witness) = open(&adapter, DoubleConfig::default());
    let mut prompt = openai_prompt("go");
    prompt.model_hint = Some(CLAUDE_MODEL.into());
    prompt.credential = Some(HarnessCredential::new(HarnessAuth::AnthropicApiKey(
        "sk-ant-mock-not-a-real-key".to_owned(),
    )));
    let outcome = turn(session.as_mut(), &prompt).await;
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, "ok");
    let request = &mock.requests()[0];
    let offered: Vec<&Value> = request["tools"]
        .as_array()
        .expect("the request carries a tools array")
        .iter()
        .collect();
    let reached = json!({
        "direct": offered
            .iter()
            .map(|tool| tool["name"].as_str().unwrap_or("?"))
            .collect::<Vec<&str>>(),
        "nested": nested_tools(offered.iter().copied()),
    });
    let pinned: Value =
        serde_json::from_str(include_str!("fixtures/claude_model_tools.json")).expect("fixture");
    assert_eq!(reached, pinned, "the Anthropic model-facing tool set moved");
    let text = request.to_string();
    for hosted in ["web_search", "web_fetch", "WebSearch", "WebFetch"] {
        assert!(
            !text.contains(hosted),
            "a hosted {hosted} tool is model-facing"
        );
    }
    assert!(text.contains("/work"));
}

/// **A request that is not a model call takes no scripted reply from the mock
/// provider.** A status-only `GET`, what a login check sends to a port it
/// takes for unbound, is answered `404` and logged nowhere, and the model call
/// after it is answered with the script's first reply; both answers are read
/// off the socket. A mock that answered every request from its script would
/// give such reads a turn's replies, and its script's end would leave the
/// turn's next model call none (MEASURED: three such reads after a Code Mode
/// wall cell's first model call left its turn running at 20 s, against 3.2 s
/// without them).
///
/// **Would red if:** the mock answered a request that is not a `POST` from its
/// script (watched: `HTTP/1.1 200 OK`, the first reply taken).
#[tokio::test]
async fn a_stray_read_takes_no_scripted_reply_from_the_mock_provider() {
    /// One HTTP/1.1 exchange on a fresh connection: the response's head and
    /// its `content-length` body, as bytes off the socket.
    async fn exchange(address: &str, request: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to the mock");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write the request");
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let text = String::from_utf8_lossy(&response).into_owned();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|line| {
                        let line = line.to_ascii_lowercase();
                        line.strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if response.len() >= end + 4 + length {
                    return text;
                }
            }
            let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
                .await
                .expect("the mock answers within 10 s")
                .expect("read the response");
            if read == 0 {
                return text;
            }
            response.extend_from_slice(&chunk[..read]);
        }
    }

    let mock = MockProvider::start(vec![message_reply("r1", "DONE", usage(1, 0, 1))]).await;
    let address = mock
        .url
        .trim_start_matches("http://")
        .trim_end_matches("/v1")
        .to_owned();

    let stray = exchange(
        &address,
        &format!("GET /backend-api/wham/usage HTTP/1.1\r\nhost: {address}\r\n\r\n"),
    )
    .await;
    assert!(stray.starts_with("HTTP/1.1 404 "), "{stray}");
    assert_eq!(mock.requests(), Vec::<Value>::new());

    let body = r#"{"model":"m"}"#;
    let call = exchange(
        &address,
        &format!(
            "POST /v1/responses HTTP/1.1\r\nhost: {address}\r\ncontent-type: \
             application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(
        call.starts_with("HTTP/1.1 200 ") && call.contains("\"delta\":\"DONE\""),
        "the model call is answered with the script's first reply: {call}"
    );
    assert_eq!(mock.requests(), vec![json!({"model": "m"})]);
}

/// **A turn that stalls fails its cell on [`TURN_BOUND`], the panic naming the
/// turn, before nextest kills the cell naming nothing.** The bound is at most
/// half the default nextest profile's kill, read off `.config/nextest.toml`
/// (its `slow-timeout` period times its `terminate-after`), so a turn its cell
/// began within the other half reaches the bound first. The cell reads a period
/// written in whole seconds (`10s`, the form the default profile uses); any
/// other form fails it, naming the period.
///
/// **Would red if:** the bound were nextest's kill itself, its value before
/// (watched: `TURN_BOUND 60s is over half of nextest's 60s kill`), which the
/// kill always reaches first, the cell's setup running before its turn: a
/// turn whose first model call the mock never answered then ended as
/// `TIMEOUT [60.010s]`, its output only `(test timed out)`, and under the 30 s
/// bound as `FAIL [30.010s]`, `the turn did not end within TURN_BOUND, 30 s`.
///
/// The same holds, against its own kill, for each cell that waits
/// [`RETRY_EXHAUSTION_BOUND`] for a turn ([`RETRY_EXHAUSTION_CELLS`]): a
/// `[[profile.default.overrides]]` entry whose `filter` names the cell sets
/// its kill to at least twice that bound.
#[test]
fn the_turn_bound_is_at_most_half_of_nextests_kill() {
    let config: toml::Value = toml::from_str(include_str!("../../../.config/nextest.toml"))
        .expect("parse .config/nextest.toml");
    let kill_of = |slow: &toml::Value| {
        let period = slow["period"].as_str().expect("a slow-timeout period");
        let seconds = period
            .strip_suffix('s')
            .and_then(|seconds| seconds.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("a period in whole seconds, not `{period}`"));
        let periods = slow["terminate-after"]
            .as_integer()
            .and_then(|periods| u64::try_from(periods).ok())
            .expect("a terminate-after count");
        Duration::from_secs(seconds * periods)
    };
    let kill = kill_of(&config["profile"]["default"]["slow-timeout"]);
    assert!(
        TURN_BOUND * 2 <= kill,
        "TURN_BOUND {}s is over half of nextest's {}s kill",
        TURN_BOUND.as_secs(),
        kill.as_secs()
    );
    let overrides = config["profile"]["default"]
        .get("overrides")
        .and_then(toml::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for cell in RETRY_EXHAUSTION_CELLS {
        let kill = overrides
            .iter()
            .filter(|entry| {
                entry
                    .get("filter")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|filter| filter.contains(cell))
            })
            .find_map(|entry| entry.get("slow-timeout").map(kill_of))
            .unwrap_or_else(|| {
                panic!("no `[[profile.default.overrides]]` slow-timeout names `{cell}`")
            });
        assert!(
            RETRY_EXHAUSTION_BOUND * 2 <= kill,
            "{cell}: RETRY_EXHAUSTION_BOUND {}s is over half of its {}s kill",
            RETRY_EXHAUSTION_BOUND.as_secs(),
            kill.as_secs()
        );
    }
}

/// The cells that wait [`RETRY_EXHAUSTION_BOUND`] for a turn whose Messages
/// call exhausts nanocode's retries.
const RETRY_EXHAUSTION_CELLS: [&str; 3] = [
    "a_transient_failure_past_the_harness_retries_is_classed_transient",
    "an_anthropic_dropped_model_connection_after_a_tool_frame_is_a_transient_failure",
    "a_refused_messages_connect_is_marked_conservatively",
];
