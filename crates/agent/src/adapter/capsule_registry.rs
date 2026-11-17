//! The kind→adapter map the capsule worker's generic dispatch reads.
//!
//! [`AgentAdapter`] is the protocol contract; [`AdapterKind`] is the
//! capsule's own word for which contract it authorized. Something must
//! answer "which adapter does this kind open a session on" — and exactly
//! once, so a new kind lands its capsule tier by registering here, never by
//! growing a new dispatch arm in the worker.
//!
//! The registry is built once at worker admission and serves `Arc`s: an
//! adapter value is a stateless protocol driver, so every session of one
//! kind can share the value — the state lives in the session it opens.
//!
//! The PRODUCTION registry is built in kata-worker
//! (`kata_worker::adapter_registry::production`), not here: the embedded
//! harness's adapter lives in `kata-agent-nanocode`, which depends on this
//! crate, so only a crate above both can name every adapter.

use std::collections::BTreeMap;
use std::sync::Arc;

use kata_types::agent::AdapterKind;

use crate::adapter::AgentAdapter;

/// The ONE lookup the capsule worker's `Agent` arm makes: the adapter a
/// turn's declared kind opens sessions on.
pub trait AgentAdapterRegistry: Send + Sync {
    /// The adapter for `kind`, or `None` when this build carries none —
    /// which is a refusal (`adapter_unavailable`), never a fallback: a
    /// capsule's adapter is its authorization's answer, and an answer this
    /// build cannot speak to is not a weaker one.
    fn adapter(&self, kind: AdapterKind) -> Option<Arc<dyn AgentAdapter>>;
}

/// A registry of one adapter value per kind. A kind with no driver gets no
/// entry: the registry answers `None` for it. The production registry
/// (`kata_worker::adapter_registry::production`) registers every kind.
pub struct StaticAgentAdapterRegistry {
    adapters: BTreeMap<AdapterKind, Arc<dyn AgentAdapter>>,
}

impl StaticAgentAdapterRegistry {
    /// Register each adapter under the kind it declares.
    ///
    /// # Panics
    ///
    /// When two adapters declare one kind: a registry that silently kept one
    /// would dispatch a kind to whichever was listed last.
    #[must_use]
    pub fn new(adapters: impl IntoIterator<Item = Arc<dyn AgentAdapter>>) -> Self {
        let mut registered = BTreeMap::new();
        for adapter in adapters {
            let kind = adapter.kind();
            assert!(
                registered.insert(kind, adapter).is_none(),
                "two adapters declare kind `{}`; a kind is registered exactly once",
                kind.as_label()
            );
        }
        Self {
            adapters: registered,
        }
    }
}

impl AgentAdapterRegistry for StaticAgentAdapterRegistry {
    fn adapter(&self, kind: AdapterKind) -> Option<Arc<dyn AgentAdapter>> {
        self.adapters.get(&kind).cloned()
    }
}
