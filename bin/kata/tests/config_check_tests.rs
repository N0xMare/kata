//! `config check` validation tests:
//! `config_check` rejects a bad `api.bind`, missing required fields, and
//! accepts a well-formed installed-main config.

use kata::cli::testing::config_check;

/// Regression pin for `kata config check`: a config that fails
/// `KataConfig::validate` (invalid `api.bind`) must produce an error,
/// NOT a cheery "parsed OK" on stdout. Before confirming this fix the
/// reviewer noted that the summary wording could mislead operators
/// into thinking validation had happened when it had not; the current
/// implementation delegates validation to `ConfigManager::load` which
/// calls `KataConfig::validate`, so a bad `api.bind` must surface as
/// a hard error.
#[test]
fn config_check_rejects_invalid_api_bind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    // A config with a structurally valid TOML shape but an
    // `api.bind` that will NOT parse as a `SocketAddr`. The rest of
    // the fields are correct so parsing succeeds and validation is
    // the only remaining gate.
    let text = r#"
[node]
id = "test-main"
data_dir = "/tmp/kata-config-check-test"

[workers]
transports = [{ type = "supervised_node" }]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "not-a-socket-address"
auth = { type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }
"#;
    std::fs::write(&path, text).unwrap();

    let result = config_check(&path);
    let err = result.expect_err(
        "config_check must reject an unparseable api.bind instead of \
         reporting the config as valid",
    );
    let chain: String = err
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" :: ");
    assert!(
        chain.contains("api.bind") || chain.contains("socket"),
        "error chain should mention api.bind validation failure; got: {chain}"
    );
}

/// Regression pin: missing required fields (e.g. `[node]`) must also
/// be rejected. TOML deserialisation fails before validation runs,
/// but either error path is acceptable — the only thing that isn't
/// is `Ok(())`.
#[test]
fn config_check_rejects_missing_required_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    // No [node] section at all — deserialisation must fail.
    let text = r#"
[api]
bind = "127.0.0.1:8400"
auth = { type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }
"#;
    std::fs::write(&path, text).unwrap();
    let result = config_check(&path);
    assert!(
        result.is_err(),
        "config_check must reject configs missing required top-level fields"
    );
}

/// Regression pin: a well-formed, fully validated config is accepted.
/// Pairs with the negative tests above to ensure the function is not
/// simply returning `Err` unconditionally.
#[test]
fn config_check_accepts_valid_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    let text = r#"
[node]
id = "happy-main"
data_dir = "/tmp/kata-config-check-happy"

[workers]
transports = [{ type = "supervised_node" }]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = { type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }
"#;
    std::fs::write(&path, text).unwrap();
    config_check(&path).expect("well-formed config must validate cleanly");
}

/// A config naming a vendor adapter this build no longer carries is refused by
/// `kata config check` as `adapter_unqualified`, and the refusal names the
/// nanocode kinds, the only harness kata ships, as the recourse. (The launch
/// `argv` such a block declared is refused before it, at parse, as an unknown
/// field: `kata_check_admits_each_nanocode_kind`.)
///
/// **Would red if:** a removed adapter label were admitted (watched: every row
/// checked clean at the commit before the vendor adapters were deleted), or the
/// refusal stopped naming the nanocode kinds.
#[test]
fn kata_config_check_refuses_a_removed_vendor_adapter_naming_nanocode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    for adapter in ["codex_app_server", "generic_acp", "grok_acp", "pi_rpc"] {
        std::fs::write(
            &path,
            format!(
                r#"
[node]
id = "removed-adapter"
data_dir = "{data}"

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.default]
adapter = "{adapter}"
"#,
                data = dir.path().join("data").display(),
            ),
        )
        .unwrap();
        let refused = config_check(&path).err().unwrap_or_else(|| {
            panic!("`kata config check` refuses a config naming the removed `{adapter}`")
        });
        let chain = format!("{refused:#}");
        assert!(
            chain.contains("adapter_unqualified")
                && chain.contains("[agents.default]")
                && chain.contains(&format!("`{adapter}`"))
                && chain.contains("`nanocode_openai`")
                && chain.contains("`nanocode_anthropic`"),
            "the refusal names `{adapter}` and the nanocode kinds: {chain}"
        );
    }
}

/// The nanocode kinds through the CLI's own `kata check --config` dispatch: a
/// pack whose stage selects an agent declaring either kind, with an `api_key`
/// credential the kind runs under, checks clean; the same block declaring a
/// launch `argv` or an `egress_extra` — no fields of an agent block, since the
/// kind fixes its launch and its capsule opens no endpoint of its own — is
/// refused by `kata check --config` and by `kata config check` alike, at
/// load, as an unknown field naming it. In-process (`kata::cli::run`,
/// `config_check`), for `gate_exclusion`'s reason above.
///
/// **Would red if:** `kata check` refused a nanocode kind the CHECK admits, or
/// either door loaded a block declaring a launch vector or an extra egress
/// authority.
#[test]
fn kata_check_admits_each_nanocode_kind() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kata.toml");
    let pack = dir.path().join("agent-pack.star");
    std::fs::write(
        &pack,
        "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review the diff\")\n\
         workflow(\"agent-pack\", root = [verdict])\n",
    )
    .unwrap();
    let check_under = |agent: &str| {
        std::fs::write(
            &config,
            format!(
                r#"
[node]
id = "nanocode-check"
data_dir = "{data}"

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.codex]
{agent}
"#,
                data = dir.path().join("data").display(),
            ),
        )
        .unwrap();
        kata::cli::run(kata::cli::Cli {
            api_url: "http://127.0.0.1:8400".to_string(),
            format: kata::cli::OutputFormat::Human,
            command: kata::cli::Command::Check {
                workflow: Some(pack.display().to_string()),
                all: false,
                deny_warnings: false,
                config: Some(config.clone()),
            },
        })
    };

    for (adapter, var) in [
        ("nanocode_openai", "OPENAI_API_KEY"),
        ("nanocode_anthropic", "ANTHROPIC_API_KEY"),
    ] {
        let credential = format!("credential = {{ mode = \"api_key\", source = \"env:{var}\" }}");
        check_under(&format!("adapter = \"{adapter}\"\n{credential}"))
            .unwrap_or_else(|refused| panic!("{adapter}: checks clean: {refused:#}"));
        for (field, value) in [
            ("argv", "[\"codex\", \"app-server\"]"),
            ("egress_extra", "[\"registry.internal:443\"]"),
        ] {
            let block = format!("adapter = \"{adapter}\"\n{field} = {value}\n{credential}");
            for (door, refused) in [
                (
                    "kata check --config",
                    check_under(&block).expect_err("the block does not load"),
                ),
                (
                    "kata config check",
                    config_check(&config).expect_err("the block does not load"),
                ),
            ] {
                let chain = format!("{refused:#}");
                assert!(
                    chain.contains("unknown field") && chain.contains(&format!("`{field}`")),
                    "{adapter}, {door}: `{field}` is refused as an unknown field: {chain}"
                );
            }
        }
    }
}

/// A hard dollar bound over the embedded harness through the CLI's own `kata
/// check --config`: a pack under `cost_bound(0.5)` whose stage selects
/// `nanocode_openai` (unpriced: its OpenAI rows are not re-verified) is refused
/// `cost_bound_unenforceable_unpriced_adapter` naming the stage and the adapter,
/// under its `env:` key and under kata's own login alike; the same pack on
/// `nanocode_anthropic` under an `env:` API key (priced by the Anthropic rows)
/// checks clean. In-process (`kata::cli::run`), for `gate_exclusion`'s reason
/// above.
///
/// **Would red if:** the hard-dollar door admitted an unpriced nanocode stage
/// (watched: `unpriceable_spend` answering `None` for the nanocode kinds), or
/// refused the priced one.
#[test]
fn kata_check_refuses_a_hard_dollar_bound_over_unpriced_nanocode_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kata.toml");
    let pack = dir.path().join("bounded-pack.star");
    std::fs::write(
        &pack,
        "verdict = stage(id = \"verdict\", agent = \"coder\", prompt = \"review the diff\")\n\
         workflow(\"bounded-pack\", root = [verdict], bounds = [cost_bound(0.5)])\n",
    )
    .unwrap();
    let check_under = |adapter: &str, credential: &str| {
        std::fs::write(
            &config,
            format!(
                r#"
[node]
id = "nanocode-hard-dollar"
data_dir = "{data}"

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.coder]
adapter = "{adapter}"
credential = {credential}
"#,
                data = dir.path().join("data").display(),
            ),
        )
        .unwrap();
        kata::cli::run(kata::cli::Cli {
            api_url: "http://127.0.0.1:8400".to_string(),
            format: kata::cli::OutputFormat::Human,
            command: kata::cli::Command::Check {
                workflow: Some(pack.display().to_string()),
                all: false,
                deny_warnings: false,
                config: Some(config.clone()),
            },
        })
    };

    for credential in [
        "{ mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }",
        "{ mode = \"subscription\", source = \"kata_login\" }",
    ] {
        let refused = check_under("nanocode_openai", credential)
            .expect_err("an unpriced nanocode stage under a hard dollar bound is refused");
        let chain = format!("{refused:#}");
        for needle in [
            "cost_bound_unenforceable_unpriced_adapter",
            "stage \"verdict\"",
            "`nanocode_openai`",
        ] {
            assert!(
                chain.contains(needle),
                "{credential}: names {needle}: {chain}"
            );
        }
    }
    check_under(
        "nanocode_anthropic",
        "{ mode = \"api_key\", source = \"env:ANTHROPIC_API_KEY\" }",
    )
    .expect("a priced nanocode_anthropic api_key stage checks clean under the bound");
}

/// `nanocode_anthropic` under `mode = "subscription"` through the CLI's own
/// `kata check --config`: a pack whose stage selects a `kata_login`
/// subscription block is refused `credential_mode_unsupported`, naming the
/// stage, the agent, the adapter and the recourse `kata login anthropic
/// --api-key`; the same block under `mode = "api_key"` checks clean.
/// In-process (`kata::cli::run`), for `gate_exclusion`'s reason above.
///
/// **Would red if:** the CHECK's door were absent (capsule assembly, judged
/// after it, then answers instead; with both absent the block is admitted and
/// every run fails at the worker), or the `api_key` block were refused too.
#[test]
fn kata_check_refuses_nanocode_anthropic_under_subscription_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kata.toml");
    let pack = dir.path().join("agent-pack.star");
    std::fs::write(
        &pack,
        "verdict = stage(id = \"verdict\", agent = \"coder\", prompt = \"review the diff\")\n\
         workflow(\"agent-pack\", root = [verdict])\n",
    )
    .unwrap();
    let check_under = |mode: &str| {
        std::fs::write(
            &config,
            format!(
                r#"
[node]
id = "nanocode-check"
data_dir = "{data}"

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.coder]
adapter = "nanocode_anthropic"
credential = {{ mode = "{mode}", source = "kata_login" }}
"#,
                data = dir.path().join("data").display(),
            ),
        )
        .unwrap();
        kata::cli::run(kata::cli::Cli {
            api_url: "http://127.0.0.1:8400".to_string(),
            format: kata::cli::OutputFormat::Human,
            command: kata::cli::Command::Check {
                workflow: Some(pack.display().to_string()),
                all: false,
                deny_warnings: false,
                config: Some(config.clone()),
            },
        })
    };

    check_under("api_key").expect("an Anthropic API-key block checks clean");
    let refused = check_under("subscription").expect_err("a Claude subscription is refused");
    let chain = format!("{refused:#}");
    for needle in [
        "credential_mode_unsupported",
        "stage \"verdict\"",
        "`coder`",
        "`nanocode_anthropic`",
        "`kata login anthropic --api-key`",
    ] {
        assert!(chain.contains(needle), "names {needle}: {chain}");
    }
    // Capsule assembly refuses the same pair after the CHECK; the CHECK's own
    // door must be the one that answers.
    assert!(
        !chain.contains("adapter_unqualified") && !chain.contains("capsule assembly refused"),
        "the CHECK's door answered: {chain}"
    );
}

/// **`kata config check` refuses every agent block the CHECK refuses on config
/// alone, by the CHECK's own name.** Each row is one `[agents.default]` block
/// whose refusal needs no workflow — a fact of the block that refuses every
/// stage selecting it. Both doors are asked: the row's `kata config check` must
/// err naming the refusal and the block, and `kata check --config` of a pack
/// whose one stage selects the block must err under the same name. A host
/// login's spelling is answered by `KataConfig::validate` at load, before
/// either door. The admitted side: a block of each nanocode kind with a
/// non-secret `env` checks clean through both, and an empty `[agents.default]` —
/// a harness block declaring no `adapter` — is refused `adapter_undeclared` by
/// both. In-process
/// (`config_check` and `kata::cli::run`), for `gate_exclusion`'s reason above.
///
/// **Would red if:** `kata config check` admitted a block the CHECK refuses on
/// config alone (watched: a nanocode block declaring `env.HOME`, admitted rc 0
/// while `kata check --config` refused it `capsule_agent_env_channel_owned`),
/// or the two doors named one block's refusal differently.
#[test]
fn kata_config_check_refuses_every_agent_block_the_check_refuses_on_config_alone() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kata.toml");
    let pack = dir.path().join("agent-pack.star");
    std::fs::write(
        &pack,
        "verdict = stage(id = \"verdict\", agent = \"default\", prompt = \"review the diff\")\n\
         workflow(\"agent-pack\", root = [verdict])\n",
    )
    .unwrap();
    let write_agent = |node: &str, agent: &str| {
        std::fs::write(
            &config,
            format!(
                r#"
[node]
id = "agent-block-check"
data_dir = "{data}"
{node}

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.default]
{agent}
"#,
                data = dir.path().join("data").display(),
            ),
        )
        .unwrap();
    };
    let check = || {
        kata::cli::run(kata::cli::Cli {
            api_url: "http://127.0.0.1:8400".to_string(),
            format: kata::cli::OutputFormat::Human,
            command: kata::cli::Command::Check {
                workflow: Some(pack.display().to_string()),
                all: false,
                deny_warnings: false,
                config: Some(config.clone()),
            },
        })
    };
    let openai_key = "credential = { mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }";
    let rows: Vec<(String, String, &str)> = vec![
        (
            String::new(),
            format!("adapter = \"nanocode_openai\"\n{openai_key}\nenv = {{ HOME = \"/tmp/h\" }}"),
            "capsule_agent_env_channel_owned",
        ),
        (
            String::new(),
            "adapter = \"nanocode_anthropic\"\ncredential = { mode = \"api_key\", source = \
             \"kata_login\" }\nenv = { HOME = \"/tmp/h\" }"
                .to_owned(),
            "capsule_agent_env_channel_owned",
        ),
        (
            String::new(),
            format!("adapter = \"nanocode_openai\"\n{openai_key}\nenv = {{ PATH = \"/bin\" }}"),
            "capsule_agent_env_channel_owned",
        ),
        (
            String::new(),
            format!(
                "adapter = \"nanocode_openai\"\n{openai_key}\nenv = {{ VENDOR_TOKEN = \"x\" }}"
            ),
            "capsule_agent_env_secret_named",
        ),
        (
            String::new(),
            "adapter = \"nanocode_openai\"\ncredential = { mode = \"bogus\", source = \
             \"kata_login\" }"
                .to_owned(),
            "credential_undeclared",
        ),
        (
            String::new(),
            "adapter = \"nanocode_openai\"".to_owned(),
            "credential_undeclared",
        ),
        (
            String::new(),
            "adapter = \"nanocode_anthropic\"\ncredential = { mode = \"subscription\", source = \
             \"kata_login\" }"
                .to_owned(),
            "credential_mode_unsupported",
        ),
        (
            String::new(),
            "adapter = \"no_such_kind\"".to_owned(),
            "adapter_unqualified",
        ),
        (String::new(), String::new(), "adapter_undeclared"),
        (
            String::new(),
            "adapter = \"codex_app_server\"".to_owned(),
            "adapter_unqualified",
        ),
        (
            String::new(),
            "adapter = \"nanocode_openai\"\ncredential = { mode = \"subscription\", source = \
             \"codex_login\" }"
                .to_owned(),
            "credential_undeclared",
        ),
    ];
    for (node, block, door) in &rows {
        write_agent(node, block);
        let refused = config_check(&config).err().unwrap_or_else(|| {
            panic!("`kata config check` refuses `{door}` for {block:?}, as the CHECK does")
        });
        let chain = format!("{refused:#}");
        assert!(
            chain.contains(door) && chain.contains("[agents.default]"),
            "config check names `{door}` and the block for {block:?}: {chain}"
        );
        let checked = check()
            .err()
            .unwrap_or_else(|| panic!("the CHECK refuses `{door}` for {block:?}"));
        let chain = format!("{checked:#}");
        assert!(
            chain.contains(door),
            "kata check --config names `{door}` for {block:?}: {chain}"
        );
    }

    for block in [
        "adapter = \"nanocode_openai\"\nmodel = \"gpt-6-luna\"\nreasoning_effort = \"medium\"\n\
         credential = { mode = \"subscription\", source = \"kata_login\" }\nenv = { TERM = \
         \"dumb\" }"
            .to_owned(),
        "adapter = \"nanocode_anthropic\"\ncredential = { mode = \"api_key\", source = \
         \"env:ANTHROPIC_API_KEY\" }\nenv = { TERM = \"dumb\" }"
            .to_owned(),
    ] {
        write_agent("", &block);
        config_check(&config).unwrap_or_else(|refused| {
            panic!("an admitted block checks clean: {block:?}: {refused:#}")
        });
        check().unwrap_or_else(|refused| {
            panic!("the CHECK admits the same block: {block:?}: {refused:#}")
        });
    }

    write_agent("", "");
    let refused = format!(
        "{:#}",
        config_check(&config).expect_err("an empty harness block declares no launch")
    );
    assert!(
        refused.contains("adapter_undeclared") && refused.contains("`[agents.default]`"),
        "kata config check names `adapter_undeclared` for the block: {refused}"
    );
    let checked = check().expect_err("the CHECK refuses an agent stage selecting an empty block");
    let chain = format!("{checked:#}");
    assert!(
        chain.contains("adapter_undeclared"),
        "kata check --config names `adapter_undeclared` for the stage: {chain}"
    );
}

/// **`kata config check` says what it refused, and no wider.** A config whose
/// `[agents.*]` blocks the CHECK refuses on config alone still LOADS — the
/// loader `kata serve` boots through (`ConfigManager::load`) accepts it and
/// boot installs the blocks unchanged; only the stages that select one are
/// refused, at check and at admission. So the refusal must not call the config
/// invalid: it states the config parsed and validated, then names EVERY
/// unservable block with its door, and the consequence for the stages that
/// select it.
///
/// **Would red if:** the refusal read "config validation failed" again, or named
/// only the first unservable block (watched at the base: both).
#[test]
fn kata_config_check_names_every_unservable_agent_block_without_calling_the_config_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[node]
id = "unservable-agent-blocks"
data_dir = "{data}"

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.default]
adapter = "no_such_kind"

[agents.reviewer]
adapter = "nanocode_openai"
"#,
            data = dir.path().join("data").display(),
        ),
    )
    .unwrap();

    kata_core::ConfigManager::load(&path)
        .expect("the loader `kata serve` boots through accepts the config");

    let refused = config_check(&path).expect_err("the unservable blocks are refused");
    let chain = format!("{refused:#}");
    assert!(
        !chain.contains("config validation failed"),
        "the config validated; calling it invalid is wider than the refusal: {chain}"
    );
    assert!(
        chain.contains("parsed and validated OK"),
        "the refusal states what passed: {chain}"
    );
    for (block, door) in [
        ("[agents.default]", "adapter_unqualified"),
        ("[agents.reviewer]", "credential_undeclared"),
    ] {
        assert!(
            chain.contains(block) && chain.contains(door),
            "every unservable block is named with its door ({block}: {door}): {chain}"
        );
    }
    assert!(
        chain.contains("every stage that selects"),
        "the refusal names its consequence — the selecting stages: {chain}"
    );
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "config_check_tests/socket_name_config_tests.rs"]
mod socket_name_config_tests;
