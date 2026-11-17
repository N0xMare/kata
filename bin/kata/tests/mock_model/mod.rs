//! A scripted model for the rig's no-spend cells: the `mock_provider` fixture on
//! the loopback, reached through the worker's `test-support` endpoint door under a
//! fake key, whose reply to each request a cell's rule decides from what the
//! request carries — its prompt, its model, whether a tool already ran.
//!
//! A [`Turn`] is what one nanocode turn does against it: an optional shell
//! command the model runs in the capsule's `/work` through one Code Mode
//! `exec_command`, then its final answer. The command runs inside the real
//! container, so its effect on `/work` is the turn's delta exactly as a model's
//! would be; the answer is the turn's final message, which a typed stage
//! validates against its contract.
//!
//! The mock keeps its own log of every request body it received, in order
//! ([`MockModel::requests`]): the witness a cell reads for which turns ran.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use crate::agent_change_rig::nanocode::{
    Harness, assert_door_open, node_environment_decl, static_toolhost,
};
use crate::agent_change_rig::{
    Fixture, Node, NodeRoot, boot_node_main, fixture_repo, node_root,
    provision_provider_with_toolhost,
};
use crate::mock_provider::{self, MockProvider, Reply};

/// A second model `nanocode_openai` knows (`gpt-6.1-sol`, beside the testing
/// pin `gpt-6-luna`): a cell that tells two agents' turns apart pins each its own
/// and reads the model each request names.
pub const SECOND_OPENAI_MODEL: &str = "gpt-6.1-sol";

/// A mock provider served by a runtime of its own, so the blocking rig never
/// starves it.
pub struct MockModel {
    pub mock: MockProvider,
    _runtime: tokio::runtime::Runtime,
}

impl MockModel {
    /// A mock whose reply to every request is `rule`'s.
    pub fn answering(rule: impl Fn(&Value) -> Reply + Send + Sync + 'static) -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime for the mock");
        let mock = runtime.block_on(MockProvider::start_responding(Arc::new(rule)));
        Self {
            mock,
            _runtime: runtime,
        }
    }

    /// A mock that answers every request as `turn` owes it.
    pub fn always(turn: Turn) -> Self {
        Self::answering(move |request| turn.reply(request))
    }

    /// The URL `harness`'s door takes: the Responses base, or the Messages URL.
    #[must_use]
    pub fn url(&self, harness: Harness) -> String {
        match harness {
            Harness::AnthropicMock => format!("{}/messages", self.mock.url),
            _ => self.mock.url.clone(),
        }
    }

    /// Every request body the mock received, in order: its own log.
    #[must_use]
    pub fn requests(&self) -> Vec<Value> {
        self.mock.requests()
    }
}

/// One scripted nanocode turn.
#[derive(Clone, Debug)]
pub struct Turn {
    first: First,
    answer: String,
    input_tokens: u64,
    output_tokens: u64,
}

/// What a turn's first response asks for.
#[derive(Clone, Debug)]
enum First {
    /// Nothing: the first response is the answer.
    Answer,
    /// A Code Mode cell running one `exec_command` of this shell line in `/work`.
    Shell(String),
    /// A Code Mode cell running this JavaScript, which calls no tool.
    Cell(String),
    /// No response at all: the request is logged and never answered.
    Held,
}

/// A count across every mock of this process, so no two responses share an id.
static RESPONSES: AtomicUsize = AtomicUsize::new(0);

impl Turn {
    /// A turn that answers `answer` at once and runs no tool.
    #[must_use]
    pub fn answer(answer: &str) -> Self {
        Self {
            first: First::Answer,
            answer: answer.to_owned(),
            input_tokens: 10,
            output_tokens: 1,
        }
    }

    /// A turn that runs `shell` in `/work` through one `exec_command`, then
    /// answers `answer`.
    #[must_use]
    pub fn running(shell: &str, answer: &str) -> Self {
        Self {
            first: First::Shell(shell.to_owned()),
            ..Self::answer(answer)
        }
    }

    /// A turn whose first response is a Code Mode cell running `code` (no
    /// tool), then answers `answer`: two sampling responses on either kind.
    #[must_use]
    pub fn computing(code: &str, answer: &str) -> Self {
        Self {
            first: First::Cell(code.to_owned()),
            ..Self::answer(answer)
        }
    }

    /// A turn whose first request the mock logs and never answers: a model
    /// call certainly outstanding for as long as the cell needs.
    #[must_use]
    pub fn held() -> Self {
        Self {
            first: First::Held,
            ..Self::answer("")
        }
    }

    /// Each response of the turn reports `input` and `output` tokens.
    #[must_use]
    pub fn usage(self, input: u64, output: u64) -> Self {
        Self {
            input_tokens: input,
            output_tokens: output,
            ..self
        }
    }

    /// The Responses reply this turn owes `request`: its first step while the
    /// request hands the model no tool output, its answer once it does.
    #[must_use]
    pub fn reply(&self, request: &Value) -> Reply {
        let id = format!("mock{}", RESPONSES.fetch_add(1, Ordering::SeqCst));
        let usage = mock_provider::usage(self.input_tokens, 0, self.output_tokens);
        if ran_a_tool(request) {
            return mock_provider::message_reply(&id, &self.answer, usage);
        }
        match &self.first {
            First::Answer => mock_provider::message_reply(&id, &self.answer, usage),
            First::Shell(shell) => mock_provider::exec_command_reply(
                &id,
                &json!({"cmd": format!("cd /work && {{ {shell}\n}}")}),
                usage,
            ),
            First::Cell(code) => mock_provider::code_reply(&id, code, usage),
            First::Held => Reply::Stall,
        }
    }

    /// The Messages reply this turn owes `request`, as [`Self::reply`] does on
    /// the Responses kind. A shell step is the Responses kind's alone.
    #[must_use]
    pub fn messages_reply(&self, request: &Value) -> Reply {
        let id = format!("mock{}", RESPONSES.fetch_add(1, Ordering::SeqCst));
        let usage = json!({"input_tokens": self.input_tokens, "output_tokens": 1});
        if ran_a_tool(request) {
            return mock_provider::claude_text_reply_using(&self.answer, usage, self.output_tokens);
        }
        match &self.first {
            First::Answer => {
                mock_provider::claude_text_reply_using(&self.answer, usage, self.output_tokens)
            }
            First::Cell(code) => {
                mock_provider::claude_code_reply_using(&id, code, usage, self.output_tokens)
            }
            First::Held => Reply::Stall,
            First::Shell(_) => panic!("a scripted Messages turn runs no shell step"),
        }
    }
}

/// Whether `request` hands the model a tool's output: a Responses `*_call_output`
/// input item or a Messages `tool_result` block — the turn's command ran.
#[must_use]
pub fn ran_a_tool(request: &Value) -> bool {
    let responses = request["input"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|item| {
            item["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("_call_output"))
        });
    let messages = request["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|message| message["content"].as_array())
        .flatten()
        .any(|block| block["type"] == "tool_result");
    responses || messages
}

/// Whether any text `request` carries holds `needle` (as its JSON spells it).
#[must_use]
pub fn mentions(request: &Value, needle: &str) -> bool {
    request.to_string().contains(needle)
}

/// The model `request` names.
#[must_use]
pub fn model_of(request: &Value) -> &str {
    request["model"].as_str().unwrap_or("")
}

/// One `[agents.<label>]` a mock node declares: `harness` (a mock kind) pinned to
/// `model`, under the fake key the worker's environment carries.
#[derive(Clone, Copy, Debug)]
pub struct MockAgent<'a> {
    pub label: &'a str,
    pub harness: Harness,
    pub model: &'a str,
}

impl<'a> MockAgent<'a> {
    /// A `nanocode_openai` agent pinned to the owner's testing model.
    #[must_use]
    pub fn openai(label: &'a str) -> Self {
        Self {
            label,
            harness: Harness::OpenaiMock,
            model: crate::agent_change_rig::nanocode::OPENAI_MODEL,
        }
    }

    fn decl(self) -> String {
        let (credential_var, adapter) = match self.harness {
            Harness::OpenaiMock => ("OPENAI_API_KEY", "nanocode_openai"),
            Harness::AnthropicMock => ("ANTHROPIC_API_KEY", "nanocode_anthropic"),
            other => panic!("a mock node declares only mock kinds, not {other:?}"),
        };
        format!(
            "[agents.{label}]\nadapter = \"{adapter}\"\nmodel = \"{model}\"\n\
             reasoning_effort = \"medium\"\ncredential = {{ mode = \"api_key\", source = \
             \"env:{credential_var}\" }}\n",
            label = self.label,
            model = self.model,
        )
    }
}

/// A node on the rig's fixture whose one agent is `nanocode_openai` against
/// `model`, under `label`.
pub fn mock_node(model: &MockModel, label: &str) -> Node {
    let root = node_root();
    let fixture = fixture_repo(root.path());
    mock_node_on(
        root,
        fixture,
        model,
        &[MockAgent::openai(label)],
        "agent-change-e2e",
        &[],
    )
}

/// A node on `fixture` declaring `agents` against `model`, named `node_id`;
/// `first_worker_env` is added to the first worker's environment only. Every
/// worker it starts carries each agent kind's door to `model` and its fake key,
/// and the first one's log is read for the door before the node is handed
/// back: a worker without it would send its model requests to the provider.
pub fn mock_node_on(
    root: NodeRoot,
    fixture: Fixture,
    model: &MockModel,
    agents: &[MockAgent<'_>],
    node_id: &str,
    first_worker_env: &[(String, String)],
) -> Node {
    let mut env = provision_provider_with_toolhost(root.path(), &static_toolhost());
    let mut harnesses: Vec<Harness> = agents.iter().map(|agent| agent.harness).collect();
    harnesses.dedup();
    for harness in &harnesses {
        for entry in harness.worker_env(Some(&model.url(*harness))) {
            if !env.contains(&entry) {
                env.push(entry);
            }
        }
    }
    let decls: String = agents.iter().map(|agent| agent.decl()).collect();
    let labels: Vec<&str> = agents.iter().map(|agent| agent.label).collect();
    let node = boot_node_main(
        root,
        fixture,
        node_environment_decl(node_id),
        decls,
        &labels,
        node_id,
        env,
        &[],
    )
    .start_worker_with(first_worker_env);
    for harness in harnesses {
        assert_door_open(harness, "worker daemon", &node.worker.log);
    }
    node
}

/// The `Plan` a scripted `change` pack's `plan` turn answers: the pack's
/// contract, in the shape its `json_only` prompt asks for.
pub const PLAN_ANSWER: &str = r#"{"summary": "Replace the line in src/app.txt.", "steps": ["edit src/app.txt"], "files": ["src/app.txt"], "risks": []}"#;

/// Whether `request` is the shipped `change` pack's `plan` turn: its prompt, and
/// only its, asks the model to "produce a plan for the task".
#[must_use]
pub fn is_plan(request: &Value) -> bool {
    mentions(request, "produce a plan for the task")
}

/// The reply a scripted model owes a request of a `change` pack run: `plan`'s turn
/// answers [`PLAN_ANSWER`] and writes nothing (its `/work` is read-only, and a
/// delta fails it), and every other turn is `implement`'s.
pub fn change_pack_turn(request: &Value, implement: impl FnOnce() -> Turn) -> Reply {
    if is_plan(request) {
        Turn::answer(PLAN_ANSWER).reply(request)
    } else {
        implement().reply(request)
    }
}
