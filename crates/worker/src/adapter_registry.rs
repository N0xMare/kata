//! The production agent-adapter registry: one adapter per
//! [`AdapterKind`](kata_types::agent::AdapterKind), keyed by the kind that
//! declares it.
//!
//! It lives in the worker, not in kata-agent, because the embedded harness's
//! adapter is in `kata-agent-nanocode`, which depends on kata-agent; only a
//! crate above both can name every adapter. This is the ONE place a kind is
//! registered — a kind lands its capsule tier here, never as a dispatch arm.
//!
//! The embedded harness serves both nanocode kinds through one adapter type
//! (`kata_agent_nanocode::NanocodeAdapter`), registered once per kind
//! (`the_registry_serves_every_kind`). The worker's `adapter_unavailable`
//! refusal, before the container, answers a kind the registry it was handed
//! does not serve, which only a test's registry can be.

use std::sync::Arc;

use kata_agent::adapter::AgentAdapter;
use kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry;
use kata_agent_nanocode::NanocodeAdapter;

/// One adapter per kind (`the_registry_serves_every_kind`).
///
/// Built once at worker admission, before any agent turn, which is where the
/// embedded harness's process-global Code Mode limits are installed
/// ([`kata_agent_nanocode::install_code_mode_limits`]): once per worker, never
/// per turn.
#[must_use]
pub fn production() -> StaticAgentAdapterRegistry {
    kata_agent_nanocode::install_code_mode_limits();
    StaticAgentAdapterRegistry::new([
        Arc::new(harness(NanocodeAdapter::openai())) as Arc<dyn AgentAdapter>,
        Arc::new(harness(NanocodeAdapter::anthropic())),
    ])
}

/// A shipped build's nanocode adapter: its model client talks to the
/// provider's own endpoint, and no configuration names another.
#[cfg(not(feature = "test-support"))]
const fn harness(adapter: NanocodeAdapter) -> NanocodeAdapter {
    adapter
}

/// TEST SUPPORT — a `test-support` build (never a shipped one: only
/// dev-dependencies enable the feature) points a nanocode kind's model client
/// at the URL in `KATA_TEST_NANOCODE_OPENAI_URL` (a Responses base, `…/v1`) or
/// `KATA_TEST_NANOCODE_ANTHROPIC_URL` (a Messages URL) when this process's
/// environment sets it, and logs that it did, so a live cell can drive a real
/// `kata serve` main or `kata-worker` daemon against a mock provider and first
/// confirm the door is open (`code_mode_host_live`). Unset, the adapter is the
/// shipped one.
#[cfg(feature = "test-support")]
fn harness(adapter: NanocodeAdapter) -> NanocodeAdapter {
    use kata_agent::adapter::AgentAdapter as _;
    let kind = adapter.kind();
    let var = match kind {
        kata_types::agent::AdapterKind::NanocodeAnthropic => "KATA_TEST_NANOCODE_ANTHROPIC_URL",
        kata_types::agent::AdapterKind::NanocodeOpenai => "KATA_TEST_NANOCODE_OPENAI_URL",
    };
    let Some(url) = std::env::var_os(var).and_then(|url| url.into_string().ok()) else {
        return adapter;
    };
    tracing::warn!(
        "test-support: {} model requests go to {url} (`{var}`)",
        kind.as_label()
    );
    adapter.with_endpoint(kata_agent_nanocode::adapter::TestEndpoint {
        url,
        websocket_url: None,
        max_attempts: std::num::NonZeroU32::MIN,
    })
}

#[cfg(test)]
mod tests {
    use kata_agent::adapter::capsule_registry::AgentAdapterRegistry;
    use kata_types::agent::AdapterKind;

    /// The production registry serves an adapter for every kind, each its
    /// own: the CHECK admits every kind, so a kind with no adapter would pass
    /// it and be refused `adapter_unavailable` at dispatch. A new kind cannot
    /// land without registering its adapter (`AdapterKind::ALL` is the sweep).
    ///
    /// **Would red if:** a kind were left out of `production()` (watched:
    /// `nanocode_openai` unregistered).
    #[test]
    fn the_registry_serves_every_kind() {
        let registry = super::production();
        for kind in AdapterKind::ALL {
            let adapter = registry.adapter(kind).unwrap_or_else(|| {
                panic!("{}: the production registry serves it", kind.as_label())
            });
            assert_eq!(adapter.kind(), kind, "the adapter serves its own kind");
        }
    }

    /// Building the production registry installs kata's Code Mode limits:
    /// that is how the worker installs them once at start, before any agent
    /// is built. The engine's own setter is the witness: afterwards it refuses
    /// any other limits and names the ones it holds.
    #[test]
    fn the_production_registry_installs_the_code_mode_limits() {
        let _registry = super::production();
        let kata = kata_agent_nanocode::CODE_MODE_LIMITS;
        let other = nanocode_code_mode_engine::NativeLimits {
            cell_wall: kata.cell_wall * 2,
            ..kata
        };
        assert_eq!(
            nanocode_code_mode_engine::set_native_limits(other),
            Err(kata),
            "the engine holds kata's limits"
        );
    }

    /// Two adapters declaring one kind are refused at construction, not kept
    /// last-wins.
    #[test]
    #[should_panic(expected = "a kind is registered exactly once")]
    fn a_kind_registered_twice_panics() {
        use std::sync::Arc;
        let _ = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
            Arc::new(kata_agent_nanocode::NanocodeAdapter::openai())
                as Arc<dyn kata_agent::adapter::AgentAdapter>,
            Arc::new(kata_agent_nanocode::NanocodeAdapter::openai()),
        ]);
    }
}
