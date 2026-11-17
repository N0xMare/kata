//! Queue-backed `MockAgentBackend` for testing.
//!
//! The scripting vocabulary of the workflow test harness's scripted capsule
//! worker (`kata_workflow::test_harness::ScriptedWorkerHandle`): each capsule
//! frame the worker answers pops one [`MockResponse`] FIFO, and an empty queue
//! pops [`MockResponse::Default`].
//!
//! Fixtures that drive concurrency-oriented assertions push matching
//! [`MockResponse::Rendezvous`] values. Each answer must reach the same
//! barrier, which proves overlap structurally instead of inferring it from
//! wall-clock timing.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;

use kata_types::cache::TokenUsage;
use kata_types::metering::{MeteredCost, ProviderCost, StageUsage};

/// Canned answer to one capsule frame.
///
/// `Hang` signals an error condition — the scripted worker reports a failed
/// capsule rather than actually blocking forever.
#[derive(Clone, Debug)]
pub enum MockResponse {
    /// Plain text reply.
    Text(String),
    /// Structured JSON reply (for review / grading stages).
    Json(serde_json::Value),
    /// Echo the delivered prompt back as content. Used by templating
    /// tests to prove that the runner built the capsule with the rendered
    /// prompt — the echoed content = what the agent actually saw.
    Echo,
    /// Echo the delivered agent turn's model as content.
    EchoModelHint,
    /// Error-producing reply — the scripted worker reports an agent process
    /// that ran and errored.
    Hang,
    /// A provider refusal — the scripted worker reports a failed capsule whose model
    /// request the provider refused: PROVEN NOT PERFORMED, with the `refused`
    /// provider-failure class beside it.
    ProviderRefused,
    /// Sleep `ms` milliseconds, then answer with a canned default response. Useful
    /// for timeout, cancellation, and deliberately delayed-response tests; do
    /// not use elapsed timing as a concurrency proof. The scripted worker sleeps
    /// in its receive loop, so every later frame waits unanswered behind it.
    Sleep(u64),
    /// Wait until every participant reaches the shared barrier, then answer
    /// with a canned default response. A test can give two frames the same
    /// two-party barrier to prove that both were being answered concurrently:
    /// the scripted worker waits on it off its receive loop, so the barrier's
    /// other parties may be later frames. A mutex held across the answer cannot
    /// satisfy the barrier.
    Rendezvous(Arc<tokio::sync::Barrier>),
    /// Exhaustion fallback — returned by `pop` when the queue is empty.
    Default,
}

/// Queue-backed mock agent. Handles from [`Self::share_state`] share the same
/// queue via the interior `parking_lot::Mutex`.
///
/// The mock is not `Sync`-hostile: `parking_lot::Mutex` is
/// `Send + Sync` and holds `VecDeque<MockResponse>`, so the whole struct
/// is safe to share across threads. Tests typically wrap it in an `Arc`
/// when they want multiple holders (for example a producer that `push`es
/// from one task and a consumer that `pop`s from another).
#[derive(Debug, Default)]
pub struct MockAgentBackend {
    /// `Arc` so [`Self::share_state`] hands the scripted capsule worker a second
    /// owner of THIS queue — a cloned `VecDeque` would split the script in two.
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
    /// Bumped once per capsule frame the scripted worker answers. This is
    /// THE load-bearing "model-uncalled" observable — a cache hit or a durable
    /// resume is only *verified* (not merely asserted) when this counter is read
    /// at a real value (`0` = the model was genuinely NOT re-invoked). Shared across handles via the interior `Arc`
    /// so a fixture that hands the backend to a scripted worker can still read
    /// the count by holding a [`Self::calls_handle`].
    calls: Arc<AtomicUsize>,
    /// The provider cost every answered turn states. `ProviderCost::Unstated` by
    /// default, which reports no usage; set via [`Self::with_cost_micro_usd`]
    /// to model a backend that reports its own authoritative cost.
    cost: ProviderCost,
}

impl MockAgentBackend {
    /// Construct an empty backend. `pop` will return `MockResponse::Default`
    /// until responses are pushed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a backend pre-seeded with the given responses. The first
    /// response in the input vec is the first one `pop` returns.
    #[must_use]
    pub fn with_responses(responses: Vec<MockResponse>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(VecDeque::from(responses))),
            ..Self::default()
        }
    }

    /// Report an authoritative provider cost on every response (the executor
    /// prefers this over its per-token estimate, and reports the stage as
    /// `MeteredCost::Authoritative`).
    #[must_use]
    pub fn with_cost_micro_usd(mut self, cost: u64) -> Self {
        self.cost = ProviderCost::Reported { micro_usd: cost };
        self
    }

    /// Number of capsule frames answered so far. The "model-uncalled"
    /// instrument:
    /// read it after a cache hit / durable resume / membrane replay to VERIFY
    /// the backend was genuinely not re-invoked, rather than inferring it from
    /// output-equality (which a pass-while-broken re-invocation would also
    /// satisfy).
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// A shared handle on the invocation counter, so a fixture can still read
    /// [`Self::calls`] after handing the backend to a scripted worker.
    #[must_use]
    pub fn calls_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.calls)
    }

    /// A second handle over the SAME queue, counter and cost —
    /// `MockAgentBackend` is not `Clone` because a copied queue would silently
    /// split the script; the shared interior `Mutex`/`Arc` make a second owner
    /// unambiguous. The scripted capsule worker pumps one while the cell
    /// holds the other.
    #[must_use]
    pub fn share_state(&self) -> Self {
        Self {
            responses: Arc::clone(&self.responses),
            calls: Arc::clone(&self.calls),
            cost: self.cost,
        }
    }

    /// The usage the scripted capsule worker folds into its `AgentTurnReport`:
    /// `Some` only when [`Self::with_cost_micro_usd`] set an authoritative cost.
    #[doc(hidden)]
    #[must_use]
    pub fn scripted_usage(&self) -> Option<StageUsage> {
        match self.cost {
            ProviderCost::Reported { micro_usd } => Some(StageUsage::metered(
                &TokenUsage::default(),
                MeteredCost::Authoritative { micro_usd },
                0,
            )),
            ProviderCost::Unstated => None,
        }
    }

    /// Append a single response to the tail of the queue.
    pub fn push(&self, response: MockResponse) {
        self.responses.lock().push_back(response);
    }

    /// Pop the next response from the head of the queue, falling back to
    /// `MockResponse::Default` when empty.
    #[must_use]
    pub fn pop(&self) -> MockResponse {
        self.responses
            .lock()
            .pop_front()
            .unwrap_or(MockResponse::Default)
    }

    /// Number of queued responses not yet consumed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.responses.lock().len()
    }

    /// True when no responses are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.responses.lock().is_empty()
    }
}
