//! The Anthropic kind beside `openai_turn.rs`: its adapter pointed at a mock's
//! Messages endpoint, and its prompt on an API key.

use std::num::NonZeroU32;

use kata_agent_nanocode::adapter::TestEndpoint;
use kata_agent_nanocode::{HarnessAuth, NanocodeAdapter};
use kata_types::agent::{HarnessCredential, Prompt};

use super::openai_turn::openai_prompt;

pub const CLAUDE_MODEL: &str = "claude-sonnet-4-6";

/// A prompt for the Anthropic kind, on an API key.
pub fn anthropic_prompt(text: &str) -> Prompt {
    let mut prompt = openai_prompt(text);
    prompt.model_hint = Some(CLAUDE_MODEL.into());
    prompt.credential = Some(HarnessCredential::new(HarnessAuth::AnthropicApiKey(
        "sk-ant-placeholder".to_owned(),
    )));
    prompt
}

/// The Anthropic kind over a mock's Messages endpoint (`<url>/messages`).
pub fn anthropic(url: &str) -> NanocodeAdapter {
    NanocodeAdapter::anthropic().with_endpoint(TestEndpoint {
        url: format!("{url}/messages"),
        websocket_url: None,
        max_attempts: NonZeroU32::MIN,
    })
}
