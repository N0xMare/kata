//! One OpenAI-kind nanocode turn through the adapter: the attempt scope, the
//! prompt, the adapter pointed at a mock provider, and the bounded turn.
//! Shared by every test binary that drives the adapter against the mocks.

use std::num::NonZeroU32;
use std::time::Duration;

use kata_agent::adapter::session::CancelToken;
use kata_agent::adapter::{AgentAdapter, AgentSession, AttemptScope, SessionSeed, TurnOutcome};
use kata_agent_nanocode::adapter::TestEndpoint;
use kata_agent_nanocode::{HarnessAuth, NanocodeAdapter};
use kata_types::agent::{HarnessCredential, Prompt};
use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, CAPSULE_OUTPUT_BYTES, CapsuleBudgets, CapsuleId, GuestAccess,
    GuestMapping, GuestPath,
};
use kata_types::primitives::ContentHash;
use ulid::Ulid;

use super::toolhost_double::{self, DoubleConfig, DoubleWitness};

pub const MODEL: &str = "gpt-6-luna";

pub fn scope_with(seed: u8, output_bytes: u64) -> AttemptScope {
    let artifact = ArtifactRef::new(
        object_id_for_canonical_bytes(b"{\"tree\":\"work\"}"),
        4_096,
        ArtifactPrivacy::Public,
    )
    .id();
    AttemptScope::new(
        Ulid::new(),
        SessionSeed::new(ContentHash::new([seed; 32])),
        vec![GuestMapping {
            artifact,
            guest_path: GuestPath::new("/work").expect("/work"),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleBudgets {
            wall_time_ms: 120_000,
            output_bytes,
            memory_bytes: 2 << 30,
            process_count: 64,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        CapsuleId(ContentHash::new([9; 32])),
        kata_types::redaction::LiftedSecrets::none(),
    )
}

pub fn scope() -> AttemptScope {
    scope_with(7, CAPSULE_OUTPUT_BYTES)
}

pub fn openai_prompt(text: &str) -> Prompt {
    Prompt {
        text: text.to_owned(),
        model_hint: Some(MODEL.into()),
        effort_hint: None,
        output_schema: None,
        credential: Some(HarnessCredential::new(HarnessAuth::OpenAi(
            nanocode_backend_codex::client::OpenAiAuth::api_key("sk-mock-not-a-real-key"),
        ))),
    }
}

pub fn openai(url: &str, websocket_url: Option<&str>) -> NanocodeAdapter {
    NanocodeAdapter::openai().with_endpoint(TestEndpoint {
        url: url.to_owned(),
        websocket_url: websocket_url.map(str::to_owned),
        max_attempts: NonZeroU32::MIN,
    })
}

pub fn open(
    adapter: &NanocodeAdapter,
    config: DoubleConfig,
) -> (Box<dyn AgentSession>, DoubleWitness) {
    open_scoped(adapter, config, scope())
}

pub fn open_scoped(
    adapter: &NanocodeAdapter,
    config: DoubleConfig,
    scope: AttemptScope,
) -> (Box<dyn AgentSession>, DoubleWitness) {
    let (process, witness) = toolhost_double::start(config);
    let session = adapter
        .open(scope, process)
        .unwrap_or_else(|refusal| panic!("the nanocode adapter refused to open: {refusal}"));
    (session, witness)
}

/// How long [`turn`] and [`cancellable_turn`] wait for one turn, and
/// [`bounded`] for a cell's own wait beside or after one: at most half
/// the default nextest profile's kill (its `slow-timeout`, 10 s × 6 = 60 s in
/// `.config/nextest.toml`; `nanocode_qualification`'s
/// `the_turn_bound_is_at_most_half_of_nextests_kill`). A turn still running at
/// the bound fails its cell here, the panic naming the turn; nextest's kill
/// names nothing (a bare `TIMEOUT`). The bound comes first for a turn its cell
/// began within the other half. In a measured full-suite run no passing cell
/// that runs such a turn in its own process took over 20.1 s all told.
pub const TURN_BOUND: Duration = Duration::from_secs(30);

/// One turn, bounded by [`TURN_BOUND`].
pub async fn turn(session: &mut dyn AgentSession, prompt: &Prompt) -> TurnOutcome {
    cancellable_turn(session, prompt, &CancelToken::new()).await
}

/// One turn under the caller's cancel token, bounded by [`TURN_BOUND`].
pub async fn cancellable_turn(
    session: &mut dyn AgentSession,
    prompt: &Prompt,
    cancel: &CancelToken,
) -> TurnOutcome {
    tokio::time::timeout(TURN_BOUND, session.prompt(prompt, cancel))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the turn did not end within TURN_BOUND, {} s",
                TURN_BOUND.as_secs()
            )
        })
}

/// A cell's own wait beside or after a turn — the cancel it fires, a process it
/// waits out — bounded by [`TURN_BOUND`], so a wait that never ends fails its
/// cell naming `what` rather than ending as nextest's bare `TIMEOUT`.
pub async fn bounded<T>(what: &str, wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TURN_BOUND, wait)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{what} did not happen within TURN_BOUND, {} s",
                TURN_BOUND.as_secs()
            )
        })
}
