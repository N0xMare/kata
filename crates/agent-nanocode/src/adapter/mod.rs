//! The nanocode adapter: kata's `AgentAdapter` for the two harness kinds,
//! [`AdapterKind::NanocodeOpenai`] and [`AdapterKind::NanocodeAnthropic`].
//!
//! # Where everything runs
//!
//! nanocode's agent loop runs HERE, in the process hosting the worker, and its
//! model connections leave from this process. The `InteractiveProcess` the worker
//! hands [`NanocodeAdapter::open`] is `kata-toolhost`, the
//! capsule's init, and every tool the model calls reaches it as a frame
//! (`seam.rs` over `toolhost_client.rs`). The adapter builds no `Command` and
//! names no host path; `crates/agent/tests/adapter_contract.rs` reads these
//! files.
//!
//! # What this adapter refuses, by name
//!
//! Every refusal is pre-watermark (`TurnOutcome::Refused`, nothing issued):
//! * `toolhost_absent` — the capsule's init stated no `Hello`;
//! * `toolhost_mismatch` — its `Hello` names another protocol or source digest;
//! * `credential_unavailable` — the prompt carries no harness credential of
//!   this kind's provider;
//! * `agent_effort_unsupported` — a declared effort nanocode does not name;
//! * `harness_tool_set_mismatch` — the host tool set is not exactly kata's, or
//!   carries a dynamic or attachable provider;
//! * `agent_model_undeclared` — the prompt names no model, and nanocode's own
//!   default is never chosen;
//! * `project_instructions_unreadable` — `/work/AGENTS.md` exists and is not
//!   readable as text (a toolhost `FileError`, or not UTF-8);
//! * `workspace_unreadable` — the Anthropic kind could not read whether
//!   `/work/.git` exists (a toolhost `FileError` other than `EISDIR`), which its
//!   environment states to the model;
//! * `harness_build_failed` — nanocode refused the configuration;
//! * `model_unreachable` — the turn failed before any Generation attempt;
//! * `toolhost_lost` — the toolhost broke before any Generation attempt;
//! * `one_turn_per_session` — one kata attempt is one nanocode turn.
//!
//! # Code Mode limits
//!
//! nanocode's Code Mode evaluates model-authored JavaScript in djs, through the
//! vendored engine crate, in an interpreter process of its own per cell
//! (`kata_code_mode_host`). Its memory, thread-stack, per-cell wall-time and
//! per-cell output limits and the live-host cap ([`crate::CODE_MODE_LIMITS`])
//! are process-global,
//! so the worker installs them once at start through
//! [`crate::install_code_mode_limits`], not per turn; this adapter installs
//! nothing. A limit hit ends that cell with an error the model reads, and the turn
//! goes on, within what [`crate::CODE_MODE_LIMITS`] states the wall limit can
//! interrupt (`tests/code_mode_through_adapter.rs`,
//! `tests/code_mode_wall_through_adapter.rs`). A session opened in a process that
//! never ran the installer evaluates its cells unbounded.

use kata_agent::adapter::{
    AgentAdapter, AgentSession, AttemptScope, InteractiveProcess, OpenRefusal,
};
use kata_types::agent::AdapterKind;

mod events;
mod platform;
mod seam;
mod session;
mod toolhost_client;

pub use session::NanocodeSession;

pub(crate) use seam::{WORKSPACE, host_tool_definitions};
#[cfg(test)]
pub(crate) use session::BYPASS_STEERS;
pub(crate) use session::{
    CAPSULE_SHELL, CAPSULE_STATEMENT, PLATFORM, TIMEZONE, removed_system_blocks,
};

/// The credential the worker loads for a harness turn, carried to the adapter
/// in a [`kata_types::agent::HarnessCredential`]. The worker builds it before
/// the container launches; the adapter refuses `credential_unavailable` when the
/// carrier holds anything else, or the other provider's arm.
#[derive(Clone)]
pub enum HarnessAuth {
    /// nanocode's OpenAI auth: an API key, or kata's own ChatGPT login source.
    OpenAi(nanocode_backend_codex::client::OpenAiAuth),
    /// An Anthropic API key.
    AnthropicApiKey(String),
}

impl HarnessAuth {
    /// An API key for `kind`'s provider: the carrier of an `env:<VAR>`
    /// credential, which the worker builds before the container launches.
    #[must_use]
    pub fn api_key(kind: AdapterKind, key: String) -> Self {
        match kind {
            AdapterKind::NanocodeOpenai => {
                Self::OpenAi(nanocode_backend_codex::client::OpenAiAuth::api_key(key))
            }
            AdapterKind::NanocodeAnthropic => Self::AnthropicApiKey(key),
        }
    }

    /// Whether nanocode's model clients can send `key`: each sends an API key
    /// as an HTTP header value (the Anthropic client's `x-api-key`, built by
    /// `http::HeaderValue::from_str` in `ClaudeClient::post`; the OpenAI
    /// client's `Authorization: Bearer <key>`, built by reqwest's
    /// `RequestBuilder::bearer_auth`), and `http`'s `HeaderValue` refuses
    /// exactly a value holding a byte below 0x20 other than a horizontal tab,
    /// or 0x7F. Such a key fails the turn's first model request before it is
    /// sent, so the worker refuses it before the container. An empty key, or
    /// one with spaces, is a header value: the provider answers it.
    #[must_use]
    pub fn is_sendable_api_key(key: &str) -> bool {
        reqwest::header::HeaderValue::from_str(key).is_ok()
    }
}

impl std::fmt::Debug for HarnessAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OpenAi(_) => "HarnessAuth::OpenAi(<redacted>)",
            Self::AnthropicApiKey(_) => "HarnessAuth::AnthropicApiKey(<redacted>)",
        })
    }
}

/// Where a session's model client connects. Production uses nanocode's own
/// provider endpoints; only `test-support` can point it elsewhere.
#[derive(Clone, Debug, Default)]
pub(crate) struct Endpoint {
    #[cfg(feature = "test-support")]
    pub(crate) test: Option<TestEndpoint>,
}

/// A mock provider endpoint. Test support only: no production config key names
/// a model endpoint.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
pub struct TestEndpoint {
    /// The Responses API base URL (`…/v1`), or the Messages URL for the
    /// Anthropic kind.
    pub url: String,
    /// The Responses WebSocket URL; `None` runs the HTTPS transport.
    pub websocket_url: Option<String>,
}

/// The adapter for one harness kind. Stateless: a session holds the turn.
#[derive(Debug)]
pub struct NanocodeAdapter {
    kind: AdapterKind,
    endpoint: Endpoint,
}

impl NanocodeAdapter {
    /// The OpenAI Responses kind.
    #[must_use]
    pub fn openai() -> Self {
        Self {
            kind: AdapterKind::NanocodeOpenai,
            endpoint: Endpoint::default(),
        }
    }

    /// The Anthropic Messages kind.
    #[must_use]
    pub fn anthropic() -> Self {
        Self {
            kind: AdapterKind::NanocodeAnthropic,
            endpoint: Endpoint::default(),
        }
    }

    /// Point every session at a mock provider.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: TestEndpoint) -> Self {
        self.endpoint.test = Some(endpoint);
        self
    }
}

impl AgentAdapter for NanocodeAdapter {
    fn kind(&self) -> AdapterKind {
        self.kind
    }

    /// Takes the toolhost's stdin and stdout (its stderr stays with the worker,
    /// which drains it into the capture spool) and checks the scope maps
    /// `/work`. Performs no model call and reads no frame: the handshake is the
    /// start of `prompt`.
    fn open(
        &self,
        scope: AttemptScope,
        mut process: Box<dyn InteractiveProcess>,
    ) -> Result<Box<dyn AgentSession>, OpenRefusal> {
        if !scope
            .guest_paths()
            .any(|path| path.as_str() == seam::WORKSPACE)
        {
            return Err(OpenRefusal::Scope {
                reason: format!(
                    "a nanocode turn needs the capsule's `{}` mapping, and this scope has none",
                    seam::WORKSPACE
                ),
            });
        }
        let stdin = process
            .take_stdin()
            .ok_or(OpenRefusal::StreamUnavailable { stream: "stdin" })?;
        let stdout = process
            .take_stdout()
            .ok_or(OpenRefusal::StreamUnavailable { stream: "stdout" })?;
        Ok(Box::new(NanocodeSession::new(
            self.kind,
            self.endpoint.clone(),
            scope,
            process,
            stdin,
            stdout,
        )))
    }
}

#[cfg(test)]
mod tests {
    use kata_types::agent::AdapterKind;

    use super::HarnessAuth;

    /// **A harness credential's `Debug` names its arm and never its key.** All a
    /// `{:?}` of the carrier (a log field, a panic message) may learn is which
    /// provider's credential it is.
    ///
    /// **Would red if:** the impl printed the key (a derived `Debug`), or
    /// printed nothing at all (the nightly mutation sample's `fmt ->
    /// Ok(Default::default())` survivor: an empty rendering that hides the arm).
    #[test]
    fn a_harness_credential_debug_names_its_arm_and_never_its_key() {
        let key = "sk-kata-redaction-probe-0123456789";
        for (auth, arm) in [
            (
                HarnessAuth::api_key(AdapterKind::NanocodeOpenai, key.to_owned()),
                "HarnessAuth::OpenAi(<redacted>)",
            ),
            (
                HarnessAuth::api_key(AdapterKind::NanocodeAnthropic, key.to_owned()),
                "HarnessAuth::AnthropicApiKey(<redacted>)",
            ),
        ] {
            for rendered in [format!("{auth:?}"), format!("{auth:#?}")] {
                assert_eq!(rendered, arm);
                assert!(!rendered.contains(key), "{rendered}");
            }
        }
    }
}
