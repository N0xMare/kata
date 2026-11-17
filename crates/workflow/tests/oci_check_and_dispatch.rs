//! The one engine, observed through a SECOND raw
//! rusqlite handle and through the frame a stub worker actually received.
//!
//! # Invariant
//!
//! EVERY durable assertion here reads `operational.db` through a connection this file
//! opens itself. Asking `OperationalDb` whether `OperationalDb` recorded the dispatch is
//! the shape that has let composition defects in this tree ship green, so the typed
//! readers are never the witness.
//!
//! The frame assertions read the value that came out of the WORKER SIDE of a real
//! `InProcessTransport` — i.e. the bytes the production send boundary handed a worker —
//! rather than the value the dispatcher was holding.
//!
//! # What is NOT here, and where it is
//!
//! * The end-to-end live suite: `crates/workflow/tests/oci_stage_live.rs`,
//!   `#[ignore]`d on the AppArmor precondition named there.

use std::path::Path;
use std::sync::Arc;

use kata_core::store::cas::CasStore;
use kata_core::{EnvironmentDeclaration, OperationalDb};
use kata_program::execution_program::compile_starlark_execution_program;
use kata_transport::types::DispatchFrame;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use kata_types::execution_contract::EnvironmentId;
use kata_types::primitives::ContentHash;
use kata_types::workflow::StageId;
use kata_workflow::capsule_assembly::RenderedCommand;
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::runner::WorkflowRunner;
use smol_str::SmolStr;
use ulid::Ulid;

/// The SHIPPED shell pack the capsule class is defined over — `include_str!`
/// rather than a copy, so a fixture cannot stop being the shipped pack when the real file
/// moves.
const SHIPPED_PACK: &str =
    include_str!("../../../workflows/smoke/sandbox-smoke-shell-offline.star");
const SHIPPED_STAGE: &str = "probe";
const WORKER: &str = "worker-capsule-1";
const ENVIRONMENT_LABEL: &str = "pkgs-static-busybox";
const ROOT_STAGE_ID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";

// ---------------------------------------------------------------------------
// Check-time class door
// ---------------------------------------------------------------------------

/// A model stage, which has no capsule form.
const MODEL_PACK: &str = "verdict = stage(\n\
     \x20   id = \"verdict\",\n\
     \x20   agent = \"claude_code\",\n\
     \x20   prompt = \"review the diff\",\n\
     )\n\
     workflow(\"model-pack\", root = [verdict])\n";

#[test]
fn an_agent_stage_with_no_agent_declaration_is_refused_at_check_under_the_oci_profile() {
    // The profile is PROCESS-INSTALLED (`kata_types::node_profile`), the same mechanism
    // `[containment]` uses, and nextest runs each test in its own process — so installing
    // it here binds this cell and no sibling. No `[agents.claude_code]` is installed,
    // which is exactly what an uninstalled process observes.
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::new());
    let refusal = compile_starlark_execution_program(MODEL_PACK, "model-pack.star", &[])
        .expect_err("an agent stage with no `[agents.<label>]` declaration is refused at CHECK")
        .to_string();
    assert!(
        refusal.contains("adapter_undeclared"),
        "the refusal is BY NAME so an operator meets it on purpose: {refusal}"
    );
    assert!(
        refusal.contains("verdict") && refusal.contains("claude_code"),
        "the refusal must name the stage and the label it judged: {refusal}"
    );
    assert!(
        refusal.contains("Declare `[agents.claude_code] adapter`")
            && refusal.contains(
                "`\"nanocode_openai\"` or `\"nanocode_anthropic\"`, the harness kata ships"
            ),
        "the refusal must name the recourse — declare the adapter, the shipped harness first — \
         rather than a silent fallback: {refusal}"
    );
}

/// THE REFUSED SET, every arm by name: an adapter label this build cannot
/// speak (a removed vendor adapter's included), and a block declaring no
/// adapter at all.
#[test]
fn an_agent_stage_refuses_by_name_for_each_undeclared_and_unqualified_case() {
    kata_types::node_profile::mark_node_installed();
    for (case, adapter, named) in [
        (
            "an adapter label this build cannot speak",
            Some("imaginary_adapter".to_owned()),
            "adapter_unqualified",
        ),
        (
            "a removed vendor adapter",
            Some("codex_app_server".to_owned()),
            "adapter_unqualified",
        ),
        ("no adapter declared at all", None, "adapter_undeclared"),
    ] {
        let mut agents = std::collections::BTreeMap::new();
        agents.insert(
            "codex".to_owned(),
            kata_types::config::AgentBackendConfig::Harness {
                model: None,
                reasoning_effort: None,
                adapter,
                credential: None,
                env: std::collections::BTreeMap::new(),
            },
        );
        kata_types::node_profile::install_node_agents(agents);
        let refusal = compile_starlark_execution_program(
            "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review it\")\n\
             workflow(\"agent-pack\", root = [verdict])\n",
            "agent-pack.star",
            &[],
        )
        .expect_err("the case is refused at CHECK")
        .to_string();
        assert!(
            refusal.contains(named),
            "{case}: the refusal is BY NAME: {refusal}"
        );
        assert!(
            refusal.contains("verdict") && refusal.contains("codex"),
            "{case}: the refusal names the stage and the label: {refusal}"
        );
    }
}

/// `adapter_unqualified` IS EXACTLY A LABEL THAT NAMES NO KIND. Every kind's own
/// label, with the launch its kind takes and a credential it runs under, is
/// never refused by that name at CHECK; each spelling that names no kind (an
/// unknown word, a removed vendor adapter's label, a case variant, a hyphenated
/// init spelling, a kind's prefix) is, naming the stage, the agent and the
/// label, and naming every kind the build carries as the recourse — the answer
/// `capsule_launch` gives assembly and `kata doctor` for the same block.
///
/// **Would red if:** a kind's own label were refused `adapter_unqualified`
/// (watched: a branch refusing `nanocode_anthropic`), or a label that names no
/// kind passed the door.
#[test]
fn adapter_unqualified_is_exactly_a_label_that_names_no_kind_at_check() {
    kata_types::node_profile::mark_node_installed();
    let carried: Vec<String> = kata_types::agent::AdapterKind::ALL
        .into_iter()
        .map(|kind| format!("`{}`", kind.as_label()))
        .collect();
    for kind in kata_types::agent::AdapterKind::ALL {
        let label = kind.as_label();
        let credential = Some(kata_types::config::AgentCredentialDecl {
            mode: "api_key".to_owned(),
            source: "env:ANTHROPIC_API_KEY".to_owned(),
        });
        install_agents(&[("codex", launchable_agent(label, credential))]);
        if let Err(refusal) = check_one_agent_pack() {
            assert!(
                !refusal.contains("adapter_unqualified"),
                "{label}: its own label is never adapter_unqualified: {refusal}"
            );
        }
    }
    for label in [
        "imaginary_adapter",
        "codex_app_server",
        "Codex_App_Server",
        "nanocode-openai",
        "Nanocode_OpenAI",
        "nanocode",
    ] {
        install_one_agent(label, None);
        let refusal =
            check_one_agent_pack().expect_err(&format!("`{label}` names no kind and is admitted"));
        assert!(
            refusal.contains("adapter_unqualified:")
                && refusal.contains(&format!("declares adapter `{label}`"))
                && refusal.contains("\"verdict\"")
                && refusal.contains("`codex`"),
            "`{label}`: refused by name: {refusal}"
        );
        assert!(
            refusal.contains(&format!("the kinds it carries are {}", carried.join(", "))),
            "`{label}`: the recourse names every carried kind: {refusal}"
        );
    }
}

/// A NANOCODE BLOCK THAT DECLARES NO CREDENTIAL IS `credential_undeclared` AT
/// CHECK, NAMING ITS LOGIN. The embedded harness runs in the worker on the
/// credential its block declares and on nothing else (its capsule holds no
/// vendor login), so a block declaring none would admit a stage whose every
/// turn the worker refuses after dispatch. The refused set, exactly: a block
/// of a kind whose init is `kata-toolhost` with no `credential`. Each such
/// block is refused naming the stage, the agent, the kind and the `kata login`
/// command its recourse runs; the same block with its credential is admitted.
///
/// **Would red if:** the CHECK admitted a nanocode block with no credential
/// (watched: `kata check` passed it and the worker refused the run inside the
/// turn, `credential_unavailable`, naming no login).
#[test]
fn a_nanocode_block_with_no_credential_is_refused_credential_undeclared_at_check() {
    use kata_types::agent::AdapterKind;
    kata_types::node_profile::mark_node_installed();
    for (kind, login, mode, source) in [
        (
            AdapterKind::NanocodeOpenai,
            "`kata login openai`",
            "subscription",
            "kata_login",
        ),
        (
            AdapterKind::NanocodeAnthropic,
            "`kata login anthropic --api-key`",
            "api_key",
            "env:ANTHROPIC_API_KEY",
        ),
    ] {
        let label = kind.as_label();
        install_one_agent(label, None);
        let refusal =
            check_one_agent_pack().expect_err(&format!("`{label}` with no credential is admitted"));
        assert!(
            refusal.contains("credential_undeclared:")
                && refusal.contains(&format!("adapter `{label}`"))
                && refusal.contains(login)
                && refusal.contains("\"verdict\"")
                && refusal.contains("`codex`"),
            "{label}: refused by name, naming its login: {refusal}"
        );
        install_one_agent(
            label,
            Some(kata_types::config::AgentCredentialDecl {
                mode: mode.to_owned(),
                source: source.to_owned(),
            }),
        );
        check_one_agent_pack()
            .unwrap_or_else(|refusal| panic!("`{label}` with its credential: {refusal}"));
    }
}

/// One `[agents.<label>]` block declaring `adapter` and `credential`.
fn agent_block(
    adapter: &str,
    credential: Option<kata_types::config::AgentCredentialDecl>,
) -> kata_types::config::AgentBackendConfig {
    kata_types::config::AgentBackendConfig::Harness {
        model: None,
        reasoning_effort: None,
        adapter: Some(adapter.to_owned()),
        credential,
        env: std::collections::BTreeMap::new(),
    }
}

/// Install a node with `agents`, under an egress allowlist that fills a model
/// stage's `net = "host"` union — so no refusal below can be the empty-union
/// door's.
fn install_agents(agents: &[(&str, kata_types::config::AgentBackendConfig)]) {
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str("example.com:443")
            .expect("a host:port authority"),
    ]));
    kata_types::node_profile::install_node_agents(
        agents
            .iter()
            .map(|(label, block)| ((*label).to_owned(), block.clone()))
            .collect(),
    );
}

/// Install a node whose one agent, `codex`, declares `adapter` and
/// `credential`.
fn install_one_agent(adapter: &str, credential: Option<kata_types::config::AgentCredentialDecl>) {
    install_agents(&[("codex", agent_block(adapter, credential))]);
}

fn check_one_agent_pack() -> Result<(), String> {
    compile_starlark_execution_program(
        "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review it\")\n\
         workflow(\"agent-pack\", root = [verdict])\n",
        "agent-pack.star",
        &[],
    )
    .map(drop)
    .map_err(|error| error.to_string())
}

/// `nanocode_anthropic` UNDER `subscription` IS REFUSED BY NAME AT CHECK,
/// UNDER ANY SOURCE. kata holds no Claude subscription login in this build, so
/// a block declaring `mode = "subscription"` is `credential_mode_unsupported`
/// naming the stage, the
/// agent, the adapter and the recourse (`kata login anthropic --api-key`,
/// `mode = "api_key"`), whatever its source: the door is judged right after
/// the credential parse. Under a hard dollar bound it is
/// still this refusal: the mode door is judged before the hard-dollar door. The
/// same kind under `api_key` (`kata_login`, `env:`) is admitted, and so is
/// `nanocode_openai` under `subscription`: the refused set is that one
/// kind × mode. (`env:` under `subscription` is `credential_undeclared` at the
/// parse, before this door.)
///
/// **Would red if:** the door were absent (the block is admitted, and every
/// run then fails at the worker), judged after the hard-dollar door, or wider
/// than the one pair.
#[test]
fn nanocode_anthropic_under_subscription_is_refused_credential_mode_unsupported_at_check() {
    kata_types::node_profile::mark_node_installed();
    let credential = |mode: &str, source: &str| {
        Some(kata_types::config::AgentCredentialDecl {
            mode: mode.to_owned(),
            source: source.to_owned(),
        })
    };
    let bounded = "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review it\")\n\
                   workflow(\"agent-pack\", root = [verdict], bounds = [cost_bound(0.5)])\n";
    for source in ["kata_login"] {
        install_one_agent("nanocode_anthropic", credential("subscription", source));
        for (pack, case) in [(None, "unbounded"), (Some(bounded), "under a cost_bound")] {
            let refusal = match pack {
                None => check_one_agent_pack(),
                Some(pack) => compile_starlark_execution_program(pack, "agent-pack.star", &[])
                    .map(drop)
                    .map_err(|error| error.to_string()),
            }
            .expect_err(&format!(
                "{source}, {case}: nanocode_anthropic under subscription admitted"
            ));
            assert!(
                refusal.starts_with("validation error: credential_mode_unsupported:")
                    || refusal.contains("credential_mode_unsupported: stage \"verdict\""),
                "{source}, {case}: refused by its own name: {refusal}"
            );
            assert!(
                refusal.contains("\"verdict\"")
                    && refusal.contains("`codex`")
                    && refusal.contains("`nanocode_anthropic`")
                    && refusal.contains("`kata login anthropic --api-key`")
                    && refusal.contains("mode = \"api_key\""),
                "{source}, {case}: names the stage, agent, adapter and recourse: {refusal}"
            );
        }
    }
    for (adapter, mode, source) in [
        ("nanocode_anthropic", "api_key", "kata_login"),
        ("nanocode_anthropic", "api_key", "env:ANTHROPIC_API_KEY"),
        ("nanocode_openai", "subscription", "kata_login"),
    ] {
        install_one_agent(adapter, credential(mode, source));
        let admitted = check_one_agent_pack();
        assert!(
            admitted.as_ref().is_ok(),
            "{adapter} {mode} {source}: outside the refused pair, admitted: {admitted:?}"
        );
    }
}

/// The credentials each nanocode kind runs under, as `(mode, source)`:
/// `nanocode_openai` under kata's own ChatGPT login, kata's stored API key or an
/// `env:` key; `nanocode_anthropic` under kata's stored API key or an `env:` key
/// (no Claude subscription login exists in this build).
fn nanocode_credentials(adapter: &str) -> &'static [(&'static str, &'static str)] {
    match adapter {
        "nanocode_openai" => &[
            ("subscription", "kata_login"),
            ("api_key", "kata_login"),
            ("api_key", "env:OPENAI_API_KEY"),
        ],
        "nanocode_anthropic" => &[
            ("api_key", "kata_login"),
            ("api_key", "env:ANTHROPIC_API_KEY"),
        ],
        other => panic!("`{other}` is no nanocode kind"),
    }
}

/// THE NANOCODE KINDS ARE ADMITTED AT CHECK, with the launch their kind
/// fixes. A stage selecting an agent that declares either kind, under every
/// credential the kind runs under ([`nanocode_credentials`]), compiles under
/// `oci`.
///
/// **Would red if:** the kinds were refused at CHECK (as `adapter_unqualified`
/// refused them before they qualified).
#[test]
fn a_nanocode_kind_is_admitted_at_check() {
    kata_types::node_profile::mark_node_installed();
    for adapter in ["nanocode_openai", "nanocode_anthropic"] {
        for (mode, source) in nanocode_credentials(adapter) {
            let case = format!("{adapter}, {mode} {source}");
            install_one_agent(
                adapter,
                Some(kata_types::config::AgentCredentialDecl {
                    mode: (*mode).to_owned(),
                    source: (*source).to_owned(),
                }),
            );
            check_one_agent_pack()
                .unwrap_or_else(|refusal| panic!("{case}: admitted at CHECK: {refusal}"));
        }
    }
}

/// A NANOCODE BLOCK THAT DECLARES WHAT ITS KIND FIXES IS REFUSED BY NAME AT
/// CHECK. An `env.HOME` is `capsule_agent_env_channel_owned` (kata renders the
/// capsule's `HOME` for a toolhost kind, whose init is `kata-toolhost`); the
/// same block without the declaration is admitted. A launch `argv` and an
/// `egress_extra` are no fields of the block at all: the config load refuses
/// either as an unknown field.
///
/// **Would red if:** CHECK admitted a block the assembly or the worker then
/// refuses, or judged the kind's launch by a vendor kind's rule.
#[test]
fn a_nanocode_block_declaring_what_its_kind_fixes_is_refused_at_check() {
    kata_types::node_profile::mark_node_installed();
    for adapter in ["nanocode_openai", "nanocode_anthropic"] {
        let (mode, source) = nanocode_credentials(adapter)[0];
        let credential = || {
            Some(kata_types::config::AgentCredentialDecl {
                mode: mode.to_owned(),
                source: source.to_owned(),
            })
        };
        let mut home = agent_block(adapter, credential());
        let kata_types::config::AgentBackendConfig::Harness { env, .. } = &mut home else {
            unreachable!("agent_block builds a codex-typed block")
        };
        env.insert("HOME".to_owned(), "/home/agent".to_owned());
        install_agents(&[("codex", home)]);
        let refusal = check_one_agent_pack().expect_err(&format!(
            "{adapter}, a declared env.HOME: the CHECK admitted it"
        ));
        assert!(
            refusal.contains("capsule_agent_env_channel_owned:") && refusal.contains("`env.HOME`"),
            "{adapter}, a declared env.HOME: refused by its own name: {refusal}"
        );
        install_agents(&[("codex", agent_block(adapter, credential()))]);
        check_one_agent_pack()
            .unwrap_or_else(|refusal| panic!("{adapter}: the plain block is admitted: {refusal}"));
    }
}

/// A NANOCODE BLOCK'S DECLARATION IS JUDGED BY EACH DOOR UNDER ITS OWN NAME.
/// A credential mode or source the build cannot read — a host login's
/// spelling (`codex_login`) included, since kata reads no other tool's login —
/// is `credential_undeclared`.
///
/// **Would red if:** a nanocode kind were refused by one blanket name (as
/// `adapter_unqualified` was judged first before the kinds qualified), or a
/// host login's spelling parsed into a source.
#[test]
fn a_nanocode_blocks_declaration_is_judged_by_each_door_under_its_own_name() {
    kata_types::node_profile::mark_node_installed();
    let credential = |mode: &str, source: &str| {
        Some(kata_types::config::AgentCredentialDecl {
            mode: mode.to_owned(),
            source: source.to_owned(),
        })
    };
    for adapter in ["nanocode_openai", "nanocode_anthropic"] {
        for (case, block, door) in [
            (
                "a credential mode the build cannot read",
                agent_block(adapter, credential("oauth", "env:OPENAI_API_KEY")),
                "credential_undeclared",
            ),
            (
                "a credential source the build cannot read",
                agent_block(adapter, credential("api_key", "keychain")),
                "credential_undeclared",
            ),
            (
                "a host login's spelling",
                agent_block(adapter, credential("subscription", "codex_login")),
                "credential_undeclared",
            ),
        ] {
            install_agents(&[("codex", block)]);
            let refusal = check_one_agent_pack()
                .expect_err(&format!("{adapter}, {case}: the CHECK admitted it"));
            assert!(
                refusal.contains(&format!("{door}:")),
                "{adapter}, {case}: refused {door}: {refusal}"
            );
            assert!(
                !refusal.contains("adapter_unqualified"),
                "{adapter}, {case}: the kind qualifies: {refusal}"
            );
        }
    }
}

/// A NANOCODE KIND IS ADMITTED AS A FALLBACK PANEL MEMBER. A stage whose
/// primary agent declares one nanocode kind and whose panel's next member
/// declares the other (a credential the kind runs under) compiles at
/// CHECK: every member can run a failure retry, and each is one the build
/// launches.
///
/// **Would red if:** the panel's members were judged by a narrower door than a
/// primary agent's.
#[test]
fn a_nanocode_kind_as_a_fallback_panel_member_is_admitted_at_check() {
    kata_types::node_profile::mark_node_installed();
    for (primary, adapter) in [
        ("nanocode_anthropic", "nanocode_openai"),
        ("nanocode_openai", "nanocode_anthropic"),
    ] {
        let (mode, source) = nanocode_credentials(adapter)[0];
        let (primary_mode, primary_source) = nanocode_credentials(primary)[0];
        install_agents(&[
            (
                "codex",
                agent_block(
                    primary,
                    Some(kata_types::config::AgentCredentialDecl {
                        mode: primary_mode.to_owned(),
                        source: primary_source.to_owned(),
                    }),
                ),
            ),
            (
                "fallback",
                agent_block(
                    adapter,
                    Some(kata_types::config::AgentCredentialDecl {
                        mode: mode.to_owned(),
                        source: source.to_owned(),
                    }),
                ),
            ),
        ]);
        compile_starlark_execution_program(
            "verdict = stage(id = \"verdict\", agent = [\"codex\", \"fallback\"], prompt = \"review it\")\n\
             workflow(\"agent-pack\", root = [verdict])\n",
            "agent-pack.star",
            &[],
        )
        .unwrap_or_else(|refusal| panic!("{adapter}: the panel member is admitted: {refusal}"));
    }
}

/// EVERY KIND THE BUILD CARRIES IS ADMITTED AT CHECK. An agent declaring a
/// nanocode kind, with a credential it runs under, is admitted on
/// the same node. The labels are literals, and the last assertion ties them to
/// every kind the build carries, so no kind is left unjudged.
#[test]
fn every_adapter_kind_is_admitted_at_check() {
    kata_types::node_profile::mark_node_installed();
    let harnesses = ["nanocode_openai", "nanocode_anthropic"];
    for adapter in harnesses {
        let (mode, source) = nanocode_credentials(adapter)[0];
        install_one_agent(
            adapter,
            Some(kata_types::config::AgentCredentialDecl {
                mode: mode.to_owned(),
                source: source.to_owned(),
            }),
        );
        check_one_agent_pack()
            .unwrap_or_else(|refusal| panic!("{adapter} is admitted at CHECK: {refusal}"));
    }
    let carried: std::collections::BTreeSet<&str> = kata_types::agent::AdapterKind::ALL
        .into_iter()
        .map(kata_types::agent::AdapterKind::as_label)
        .collect();
    let judged: std::collections::BTreeSet<&str> = harnesses.into_iter().collect();
    assert_eq!(carried, judged, "every carried kind is judged here");
}

#[test]
fn the_shipped_shell_pack_compiles_under_the_oci_profile() {
    kata_types::node_profile::mark_node_installed();
    let program =
        compile_starlark_execution_program(SHIPPED_PACK, "sandbox-smoke-shell-offline.star", &[])
            .expect("the shell class is the one class this profile admits");
    assert!(
        program
            .stages
            .contains_key(&StageId(SmolStr::new(SHIPPED_STAGE))),
        "the rig's own stage must be the one that compiled"
    );
}

/// `cache_policy = "model_reuse"` on a NON-AGENT stage is refused at CHECK under `oci`,
/// by name: the capsule route serves the regime for an AGENT
/// capsule (the key folds the rendered prompt, adapter, model and credential
/// reference), but a `Command` capsule makes no model request — the declaration would
/// be silently ignored, and an ignored policy is a bill.
///
/// **Would red if:** the narrowed arm (`compile.rs`'s `CachePolicy::ModelReuse`
/// refusal) keyed on `is_agent_class` were deleted — the pack would compile and its
/// policy be ignored.
#[test]
fn model_reuse_on_a_shell_stage_is_refused_at_check_under_oci() {
    const PACK: &str = "memo = stage(id = \"memo\", agent = \"shell\", prompt = \"echo hi\", \
         sandbox = \"s\", cache_policy = \"model_reuse\")\nworkflow(\"memo-pack\", root = [memo], \
         sandbox_profiles = {\"s\": sandbox_profile(workspace = \"ro\", net = \"offline\")})\n";
    kata_types::node_profile::mark_node_installed();
    let refusal = compile_starlark_execution_program(PACK, "memo.star", &[])
        .expect_err("model reuse on a shell stage is not honoured on the capsule route")
        .to_string();
    assert!(
        refusal.contains("`cache_policy = \"model_reuse\"`") && refusal.contains("AGENT capsule"),
        "refused by name, naming the one capsule arm that serves it: {refusal}"
    );
}

/// THE AGENT-CAPSULE ADMISSION — `model_reuse` on an AGENT stage is HONOURED under `oci`: the
/// capsule route reuses the agent capsule (`capsule_reuse.rs`), keyed on
/// `Capsule::reuse_key`. A read-only verdict stage compiles; a WORKSPACE-MUTATING
/// agent stage compiles too, because a capsule hit adopts the source's recorded
/// `/work` delta — the envelope-only replay clause 4 was written for is not what
/// this route does.
///
/// **Watched red:** with the clause-4 `model_reuse` arm left ungated by profile, the
/// `rw` pack refuses `cache_policy=model_reuse` even under `oci`.
#[test]
fn model_reuse_on_an_agent_stage_is_admitted_at_check_under_oci() {
    kata_types::node_profile::mark_node_installed();
    // The node's `egress_allow` fills the model stage's `net = "host"` —
    // `egress_undeclared` without it.
    install_agents(&[(
        "codex",
        kata_program::test_harness::rig_agent_backend_config(),
    )]);
    let pack = |workspace: &str| {
        format!(
            "verdict = stage(id = \"verdict\", agent = \"codex\", \
             prompt = \"inspect the diff\", sandbox = \"work\", \
             cache_policy = \"model_reuse\")\n\
             workflow(\"memo-agent\", root = [verdict], sandbox_profiles = \
             {{\"work\": sandbox_profile(workspace = \"{workspace}\", net = \"host\")}})\n"
        )
    };
    for (file, pack) in [("memo-ro.star", pack("ro")), ("memo-rw.star", pack("rw"))] {
        compile_starlark_execution_program(&pack, file, &[]).unwrap_or_else(|error| {
            panic!("{file}: model_reuse on an agent stage is honoured under oci: {error}")
        });
    }
}

/// THE SHIPPED-PACK AUDIT — the packs whose source names
/// `cache_policy = "model_reuse"` (what `rg -l 'cache_policy = "model_reuse"'
/// workflows` finds) must, under `oci`, each CHECK or refuse on a construct
/// OTHER than the regime itself: agent capsules serve the regime, so a refusal
/// still naming `cache_policy`/`model_reuse`
/// is the regression this cell watches. `self-review` only MENTIONS the literal
/// inside a comment (its stages deliberately carry no policy) and compiles
/// outright.
///
/// Measured: `self-review` CHECKS (it never authored the regime — only its
/// comment names it); `kata-loop-lite` refuses on its agent stages' posture
/// against this audit's bare node (`egress_undeclared` — no credential, no
/// `[node] egress_allow`), never on the regime. `kata-factory/kata/factory.star`
/// is not in the literal set: its builders spell the policy
/// `_model_reuse_for(agent)` (no `model_reuse` on a deterministic stage), and it
/// is a MODULE whose stages are compiled through the packs that load it — the
/// `shipped_once_host_sandbox_packs_check_under_oci`
/// audit CHECKS all four of those.
/// Outcomes are printed so the audit's blocker is verbatim in the run.
///
/// **Would red if:** `refuse_program_under_capsule_profile`'s narrowed arm were
/// reverted — both packs would refuse NAMING `cache_policy = "model_reuse"`.
#[test]
fn shipped_model_reuse_packs_never_refuse_on_the_regime_under_oci() {
    kata_types::node_profile::mark_node_installed();
    let backend = kata_program::test_harness::rig_agent_backend_config;
    // Every agent label the authoring packs name, declared as the qualified
    // adapter form `oci` admits — `shell`/`workspace_effect` are not agent
    // labels and need no declaration.
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([
        ("codex".to_owned(), backend()),
        ("default".to_owned(), backend()),
    ]));
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .join("workflows");
    let loader_roots = [
        root.join("std"),
        root.join("kata-factory"),
        root.join("examples"),
    ];
    let mut audited = 0;
    let mut outcomes = Vec::new();
    for pack in walk(&root) {
        if pack.extension().and_then(|e| e.to_str()) != Some("star") {
            continue;
        }
        let text = std::fs::read_to_string(&pack).expect("a shipped pack is readable");
        if !text.contains("cache_policy = \"model_reuse\"") {
            continue;
        }
        audited += 1;
        let mut roots = loader_roots.to_vec();
        if let Some(dir) = pack.parent() {
            roots.insert(0, dir.to_path_buf());
        }
        match kata_program::execution_program::compile_execution_program_from_file(&pack, &roots) {
            Ok(_) => outcomes.push(format!("{}: CHECKED", pack.display())),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    !message.contains("model_reuse") && !message.contains("cache_policy"),
                    "{} refused under `oci` NAMING THE REGIME — the \
                     arm is supposed to serve agent capsules now: {message}",
                    pack.display()
                );
                outcomes.push(format!("{}: refused — {message}", pack.display()));
            }
        }
    }
    eprintln!(
        "model_reuse shipped-pack audit under `oci`:\n  {}",
        outcomes.join("\n  ")
    );
    assert_eq!(
        audited, 2,
        "rg's set grew or shrank — re-audit: {outcomes:?}"
    );
}

/// `cache_policy = "content_cache"` is HONOURED under `oci` (the capsule content
/// cache), so the reuse rig `capsule-reuse-smoke` compiles.
#[test]
fn a_content_cache_shell_stage_compiles_under_oci() {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(
        include_str!("../../../workflows/smoke/capsule-reuse-smoke.star"),
        "capsule-reuse-smoke.star",
        &[],
    )
    .expect("a content-cache shell stage is honoured, not refused, under oci");
}

/// `approval = True` is NOT in that set: the capsule path
/// HONOURS the gate — `authorize_attempt` derives it from the checked stage and parks the
/// attempt — so the pack compiles under `oci`. The park itself is
/// `capsule_approval_gate.rs`'s subject.
#[test]
fn an_approval_gated_shell_stage_compiles_under_oci() {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(
        "gate = stage(id = \"gate\", agent = \"shell\", prompt = \"echo hi\", approval = True)\n\
         workflow(\"gate-pack\", root = [gate])\n",
        "construct.star",
        &[],
    )
    .expect("an approval gate is honoured, not refused, under oci");
}

/// A BLOCKING human request is ADMITTED at CHECK under `oci`: it is
/// its own program-level input wait, which holds its target until answered. A
/// non-blocking one compiles too.
#[test]
fn a_blocking_human_request_targeting_a_stage_is_admitted_at_check_under_oci() {
    let pack = |blocking: &str| {
        let timeout = if blocking == "True" {
            "timeout_ms = 60000, "
        } else {
            ""
        };
        format!(
            "decide = stage(id = \"decide\", agent = \"shell\", run = \"echo hi\")\n\
             workflow(\"hrq-pack\", root = [decide], max_human_requests = 1, human_requests = [\n\
             human_request(\"q\", stage = \"decide\", blocking = {blocking}, {timeout}\
             question = \"proceed?\", default_assumption = \"proceed\"),\n])\n"
        )
    };
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(&pack("True"), "hrq.star", &[])
        .expect("a blocking request is an input wait under oci, admitted");
    compile_starlark_execution_program(&pack("False"), "hrq.star", &[])
        .expect("a NON-blocking request parks nothing");
}

/// A shell stage that runs over NO workspace (`workspace = "scratch"`) is ADMITTED
/// at CHECK under `oci` — a scratch capsule maps the canonical empty tree at
/// `/work` read-write, and the delta it writes is recorded as `scratch_delta_*`
/// evidence and never applied. What the `/work` door still refuses
/// under `oci` is reachable only through a DECODED program: lowering
/// materializes every process stage's sandbox to the confined default, so an
/// authored stage always resolves one — a stage whose `sandbox` slot stayed
/// `None` declares no filesystem a capsule can mount.
#[test]
fn a_shell_stage_over_scratch_is_admitted_at_check_under_oci() {
    const PACK: &str = "scratchy = stage(id = \"scratchy\", agent = \"shell\", run = \"true\", \
         sandbox = \"s\")\nworkflow(\"scratch-pack\", root = [scratchy], sandbox_profiles = \
         {\"s\": sandbox_profile(workspace = \"scratch\", net = \"offline\")})\n";
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(PACK, "scratch.star", &[])
        .expect("a scratch profile IS a capsule /work under oci");
    assert_eq!(
        program.sandbox_profiles["s"].fs,
        kata_types::sandbox::FsPolicy::Scratch,
        "the checked program resolves `s` to the scratch profile"
    );

    // The remaining refused set of the /work door — a capsule stage that
    // declares no filesystem at all. No authored spelling reaches it
    // (`materialize_sandbox` fills a bare stage with the confined default,
    // whose fs IS a workspace view), so the arm is exercised the way it can
    // occur: a program read back with a `sandbox` slot still `None`.
    const BARE: &str = "bare = stage(id = \"bare\", agent = \"shell\", run = \"true\")\n\
         workflow(\"bare-pack\", root = [bare])\n";
    let mut program = compile_starlark_execution_program(BARE, "bare.star", &[])
        .expect("a bare shell stage materializes the confined default");
    let stage = program
        .stages
        .get_mut(&StageId(SmolStr::new("bare")))
        .expect("the bare stage");
    assert!(
        stage.policies.sandbox.is_some(),
        "the premise: lowering materialized a sandbox"
    );
    stage.policies.sandbox = None;
    kata_types::node_profile::mark_node_installed();
    let refusal = kata_program::execution_program::refuse_program_at_check_or_recovery(
        &program,
        &mut std::collections::BTreeSet::new(),
    )
    .expect_err("a stage with no resolved sandbox declares no /work filesystem")
    .to_string();
    assert!(
        refusal.contains("declares no filesystem a capsule can mount")
            && refusal.contains("\"bare\""),
        "the door names the stage and its remaining refused set: {refusal}"
    );
}

/// A child-invocation plan (a declared `topology` role list or
/// `dynamic_fanout`) lowers to `ExpandBounded` at the stage's own coordinate,
/// so BOTH spellings compile under `oci`. Both run over a workspace profile so
/// no posture door is in play.
#[test]
fn a_dynamic_fanout_and_a_static_topology_both_compile_under_oci() {
    let pack = |topology: &str| {
        format!(
            "fan = stage(id = \"fan\", agent = \"shell\", run = \"true\", sandbox = \"iso\", \
             topology = {topology})\nworkflow(\"fan-pack\", root = [fan], sandbox_profiles = \
             {{\"iso\": sandbox_profile(workspace = \"rw\", net = \"offline\")}})\n"
        )
    };
    let static_workers = pack(
        "topology(\"root_with_parallel_workers\", workers = [role(\"w\", agent = \"shell\")])",
    );
    let dynamic = pack(
        "topology(\"root_with_parallel_workers\", dynamic_fanout = True, \
         mutation_policy = \"owned_paths\", workers = [role(\"w\", agent = \"shell\")])",
    );
    kata_types::node_profile::mark_node_installed();
    for (spelling, source) in [("workers", &static_workers), ("dynamic_fanout", &dynamic)] {
        compile_starlark_execution_program(source, "fan.star", &[])
            .unwrap_or_else(|error| panic!("{spelling}: the pack compiles: {error}"));
    }
}

/// The DECODE door (`kata_api::executor`'s durable program decode) runs the same
/// `refuse_program_at_check_or_recovery`, and a decoded program can carry a
/// dynamic-fanout parent with NO child role — a shape Starlark cannot author. It
/// passes CHECK like any dynamic fanout: its checked template is the root alone, and
/// at runtime every request it could make names a role the plan does not declare, which
/// the request validator (`dynamic_child_requests`) refuses (`… is not declared in topology`).
#[test]
fn a_decoded_dynamic_fanout_stage_with_no_roles_passes_check_under_oci() {
    kata_types::node_profile::mark_node_installed();
    let mut program =
        compile_starlark_execution_program(SHIPPED_PACK, "sandbox-smoke-shell-offline.star", &[])
            .expect("the shipped shell pack compiles");
    let stage = program
        .stages
        .get_mut(&StageId(SmolStr::new(SHIPPED_STAGE)))
        .expect("the shipped stage");
    assert!(
        stage.invocation_envelope.children.is_empty(),
        "the premise: no child role"
    );
    stage.invocation_envelope.dynamic_fanout = true;
    kata_program::execution_program::refuse_program_at_check_or_recovery(
        &program,
        &mut std::collections::BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("a role-less dynamic fanout passes CHECK: {error}"));
}

/// The two SHIPPED shell `parallel()` packs, `include_str!`ed so a fixture cannot stop
/// being the shipped pack.
const SHIPPED_PARALLEL_PACKS: [(&str, &str); 2] = [
    (
        "parallel-smoke.star",
        include_str!("../../../workflows/smoke/parallel-smoke.star"),
    ),
    (
        "fanout-merge.star",
        include_str!("../../../workflows/examples/fanout-merge.star"),
    ),
];

/// The synthesized `parallel()` JOIN is ADMITTED under `oci`, at
/// both doors the check function runs at: through the production compile path, on both
/// shipped shell `parallel()` packs and on the shipped outputs-only join smoke; and at the
/// in-flight RECOVERY door (the same function, over the compiled program). The join is resolved
/// main-side by the submit path's divert, so no container is spent on `sh -c :` and there is
/// nothing to refuse. That the join never becomes a capsule is pinned by
/// `a_join_resolves_main_side_with_no_capsule_or_dispatch`.
#[test]
fn a_parallel_join_is_admitted_under_oci() {
    let packs = SHIPPED_PARALLEL_PACKS
        .into_iter()
        .chain([("join-outputs-smoke.star", JOIN_PACK)]);
    for (file, pack) in packs {
        kata_types::node_profile::mark_node_installed();
        let program = compile_starlark_execution_program(pack, file, &[]).unwrap_or_else(|error| {
            panic!("{file}: a parallel() join is admitted under oci: {error}")
        });
        assert!(
            program.stages.values().any(|stage| stage.synthesized
                == Some(kata_types::workflow::SynthesizedStage::ParallelJoin)),
            "{file}: the premise — the program carries the synthesized join"
        );
        kata_program::execution_program::refuse_program_at_check_or_recovery(
            &program,
            &mut std::collections::BTreeSet::new(),
        )
        .unwrap_or_else(|error| {
            panic!("{file}: the recovery door admits a join under oci: {error}")
        });
    }
}

/// An author's own fan-in stage of the join's shape — a shell `:` depending on both
/// branches, written without `parallel()` — is an ordinary shell COMMAND: it compiles under
/// `oci` and lowers to `Execute { executor: Command }`, not to `Join`. So the divert, which
/// keys on the lowered operation, sends it to the capsule path; only the synthesized
/// barrier is resolved main-side.
#[test]
fn an_authored_fan_in_stage_of_the_same_shape_is_a_capsule_command_under_oci() {
    const PACK: &str = "a = stage(id = \"a\", agent = \"shell\", run = \"true\")\n\
         b = stage(id = \"b\", agent = \"shell\", run = \"true\")\n\
         fan_in = stage(id = \"fan_in\", agent = \"shell\", run = \":\", depends_on = [\"a\", \"b\"])\n\
         workflow(\"fan-in-pack\", root = [a, b])\n";
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(PACK, "fan-in.star", &[])
        .expect("an authored fan-in stage is a shell command, not the synthesized join");
    let lowered = kata_program::execution_program::lower_stage_operation(
        &program,
        &StageId(SmolStr::new("fan_in")),
    )
    .expect("the authored fan-in lowers");
    assert!(
        matches!(
            lowered.contract.operation,
            kata_types::execution_contract::RuntimeOperation::Execute(
                kata_types::execution_contract::ExecuteOperation {
                    executor: kata_types::execution_contract::ActionExecutor::Command,
                    ..
                }
            )
        ),
        "an authored fan-in is a capsule command: {:?}",
        lowered.contract.operation
    );
}

/// A process that installs NOTHING answers `false` to `node_is_installed`; the
/// node-fact CHECK arms defer, which is what keeps `kata workflows check --all`
/// green by construction on a box with no node.
#[test]
fn a_process_that_installs_no_node_defers_node_facts() {
    assert!(!kata_types::node_profile::node_is_installed());
}

// ---------------------------------------------------------------------------
// The production submit path
// ---------------------------------------------------------------------------

struct Rig {
    /// `None` when the rig was REOPENED over a data directory another owner holds.
    dir: Option<tempfile::TempDir>,
    op_path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: CasStore,
    store: Arc<kata_core::store::SqliteWorkflowStore>,
    supervisor: Arc<WorkerPoolSupervisor>,
    dispatcher: Arc<Dispatcher>,
    /// The WORKER side of the registered transport — where a delivered frame lands.
    worker_side: Arc<InProcessTransport>,
    execution_id: Ulid,
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

/// The environment id [`declare_promoted_environment`] declares.
const ENVIRONMENT_ID: [u8; 32] = [0x5A; 32];

/// What `BootRig::boot` binds onto a production dispatcher after it declares and promotes
/// `[node] environment`: the fixture's id on this node's own platform.
fn boot_binding() -> kata_core::environment::NodeEnvironment {
    kata_core::environment::NodeEnvironment {
        environment: EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
        platform: kata_types::node_profile::node_platform()
            .expect("the reference host is x86_64-linux")
            .id(),
    }
}

/// Build the two planes, the stage-cache store that owns the same `cas.db`, a dispatcher
/// on the `oci` profile BOUND to [`boot_binding`], and ONE registered worker claiming
/// certified containment.
fn rig() -> Rig {
    rig_with(Some(boot_binding()))
}

fn rig_with(binding: Option<kata_core::environment::NodeEnvironment>) -> Rig {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let path = dir.path().to_path_buf();
    rig_over(Some(dir), &path, binding, true)
}

/// The rig over `path`: a fresh process's planes and dispatcher over whatever that data
/// directory already holds. `live_transport = false` registers the worker over a
/// transport whose receiving end is GONE, so every send to it fails.
fn rig_over(
    dir: Option<tempfile::TempDir>,
    path: &Path,
    binding: Option<kata_core::environment::NodeEnvironment>,
    live_transport: bool,
) -> Rig {
    rig_over_with_containment(
        dir,
        path,
        binding,
        live_transport,
        kata_workflow::test_harness::rig_worker_containment(),
    )
}

fn rig_over_with_containment(
    dir: Option<tempfile::TempDir>,
    path: &Path,
    binding: Option<kata_core::environment::NodeEnvironment>,
    live_transport: bool,
    containment: kata_types::containment_claim::ClaimedContainment,
) -> Rig {
    let transport = if live_transport {
        RigTransport::Live
    } else {
        RigTransport::Refusing
    };
    rig_assembled(dir, path, binding, transport, containment, None)
}

/// The main-side transport a rig registers its one worker on.
enum RigTransport {
    /// A connected in-process pair: a delivered frame lands on `Rig::worker_side`.
    Live,
    /// A registered worker whose transport is gone, so the send is refused.
    Refusing,
    /// A caller-supplied main-side transport.
    Custom(Arc<dyn kata_transport::transport::WorkerTransport>),
}

fn rig_assembled(
    dir: Option<tempfile::TempDir>,
    path: &Path,
    binding: Option<kata_core::environment::NodeEnvironment>,
    transport: RigTransport,
    containment: kata_types::containment_claim::ClaimedContainment,
    send_timeout: Option<std::time::Duration>,
) -> Rig {
    let op_path = path.join("operational.db");
    // The stage-cache store co-locates `cas.db` + `cas/` beside its own file, which is
    // the CAS the operational plane's authoritative roots resolve into (see
    // `Executor::refuse_on_dangling_authoritative_cas_root`). Opening it FIRST means the
    // rig's own `CasStore` handle below is a second handle on the same files, and the
    // operational plane is BOUND to it exactly as boot binds it
    // (`OperationalDb::open_with_cas`), which is what lets the plane read a capsule's
    // promised budget.
    let store = Arc::new(
        kata_core::store::SqliteWorkflowStore::open(path.join("workflow.db"))
            .expect("the stage-cache store opens"),
    );
    let db = Arc::new(
        OperationalDb::open_with_cas(&op_path, store.shared_cas())
            .expect("the operational plane opens"),
    );
    let cas =
        CasStore::open(path.join("cas.db"), path.join("cas")).expect("the content store opens");

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let (main_side, worker_side) = InProcessTransport::pair(8);
    let (main_side, worker_side): (Arc<dyn kata_transport::transport::WorkerTransport>, _) =
        match transport {
            RigTransport::Live => (Arc::new(main_side), worker_side),
            RigTransport::Refusing => {
                // Dropping the worker end drops the frame receiver, so the main side's
                // send is refused: a registered worker whose transport is gone.
                drop(worker_side);
                (Arc::new(main_side), InProcessTransport::pair(8).1)
            }
            RigTransport::Custom(custom) => (custom, InProcessTransport::pair(8).1),
        };
    let membrane = kata_types::identity::WorkerMembraneId(Ulid::new());
    let domain = db
        .enroll_worker_domain("execution-profile-cutover", membrane)
        .expect("the worker enrolls a membrane");
    let _peer = supervisor.register_worker_with_effect_domain(
        SmolStr::new(WORKER),
        main_side,
        vec![],
        containment,
        *kata_workflow::test_harness::oci_rig_executor_term().digest(),
        domain,
    );
    let ledger = kata_core::InFlightLedger::in_memory();
    let heartbeat = Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(30),
    ));
    let dispatcher = Dispatcher::new(Arc::clone(&supervisor), heartbeat, ledger);
    let dispatcher = match send_timeout {
        Some(send_timeout) => dispatcher.with_send_timeout(send_timeout),
        None => dispatcher,
    };
    let dispatcher = match binding {
        Some(binding) => dispatcher.with_node_environment(binding),
        None => dispatcher,
    };
    let dispatcher = Arc::new(
        dispatcher
            .with_execution_lifecycle(
                kata_workflow::execution_lifecycle::ExecutionLifecycleFace::new(Arc::clone(&db)),
            )
            .with_program_probe(std::sync::Arc::new(
                // `git` beside `sh`: a stage that `requires` it
                // must find it on the fixture environment's PATH. `getent`
                // joins them: the rig `sandbox-smoke-shell-offline`'s probe
                // stage declares it in `requires` — the fixture env is the
                // PATH these cells' `probe` capsule authorizes against.
                kata_workflow::test_harness::FixtureProgramProbe(vec!["sh", "git", "getent"]),
            )),
    );

    // The execution is ADMITTED by `put_current_program` in `runner()` — the production
    // admission door, which re-derives the program's own whole-program hash and refuses a
    // header describing different bytes. A second `submit_execution` here with a fixture
    // digest is what that door refuses, so the rig does not have one.
    let execution_id = Ulid::new();

    Rig {
        dir,
        op_path,
        db,
        cas,
        store,
        supervisor,
        dispatcher,
        worker_side: Arc::new(worker_side),
        execution_id,
    }
}

/// Declare the [`boot_binding`] environment's ROW, unpromoted — what a boot crash between
/// the commit and the promotion (K15) leaves.
fn declare_unpromoted_environment(rig: &Rig) {
    let manifest = rig
        .cas
        .put_durable(&kata_workflow::test_harness::fixture_environment_manifest_bytes())
        .expect("the manifest publishes");
    let declaration = EnvironmentDeclaration::for_staged_root(
        ENVIRONMENT_ID,
        &manifest,
        [0x5C; 32],
        ENVIRONMENT_LABEL,
        boot_binding().platform.0.0,
        ROOT_STAGE_ID,
    )
    .expect("the declaration is well formed");
    rig.db
        .declare_environment(&declaration)
        .expect("the environment declares");
}

/// Declare the [`boot_binding`] environment and PROMOTE its gc root — the rows
/// `kata_core::environment::bind_node_environment` leaves at boot (whose own cells, over a
/// real nix, are `crates/core/tests/node_environment_binding.rs`).
fn declare_promoted_environment(rig: &Rig) -> EnvironmentId {
    declare_unpromoted_environment(rig);
    rig.db
        .promote_environment_root(ENVIRONMENT_ID, chrono::Utc::now().timestamp_millis())
        .expect("the gc root promotes");
    EnvironmentId(ContentHash::new(ENVIRONMENT_ID))
}

/// The shipped pack compiled. Its own `program_hash` is what the rig admits the
/// execution under, so the runner's program and the admitted record name one program.
fn shipped_program() -> kata_program::execution_program::ExecutionProgram {
    compile_starlark_execution_program(SHIPPED_PACK, "sandbox-smoke-shell-offline.star", &[])
        .expect("the shipped pack compiles")
}

/// The second admission half `put_current_program` does not run: on a capsule
/// rig, every non-isolated execution is owed a recorded `/work` head — the ONE
/// admission-time scratch walk — before its first capsule can submit. Seeding
/// an EMPTY scratch dir is the deterministic seed: an identical re-seed
/// converges under `record_work_tree_head`, so a re-admitted execution's
/// runner helper may run this again harmlessly.
fn seed_scratch_head(rig: &Rig) {
    let scratch = tempfile::tempdir().expect("a scratch dir to seed from");
    kata_core::work_tree::publish_scratch_tree_head(
        &rig.db,
        &rig.cas,
        rig.execution_id,
        scratch.path(),
    )
    .expect("the admission seed records the root head");
}

/// Build the runner over the shipped shell pack, on the rig's planes.
fn runner(rig: &Rig) -> WorkflowRunner {
    let program = shipped_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(rig.execution_id, &program)
        .expect("the program is retained");
    seed_scratch_head(rig);
    WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
        .expect("the runner builds")
        .with_cache_store(Arc::clone(&rig.store))
}

/// The resolved directive the shipped stage's own sandbox profile produces, through the
/// production resolver.
async fn directive(rig: &Rig) -> Option<kata_types::sandbox::SandboxDirective> {
    let program = shipped_program();
    let stage = program
        .stages
        .get(&StageId(SmolStr::new(SHIPPED_STAGE)))
        .expect("the shipped stage is present");
    rig.dispatcher
        .resolve_sandbox(
            stage.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            rig.execution_id,
            stage.should_confine_to_declared_inputs(),
            stage.is_content_cacheable(),
        )
        .await
        .expect("the shipped profile resolves")
}

#[tokio::test]
async fn the_submit_path_authorizes_a_capsule_and_its_frame_crosses_the_transport() {
    let rig = rig();
    declare_promoted_environment(&rig);
    // The runner's `put_current_program` ADMITS the execution and `runner()`
    // seeds its `/work` head — the admission halves the capsule submit reads.
    let runner = runner(&rig);
    let directive = directive(&rig).await;

    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("the production capsule submit path runs end to end");

    // -- THE FRAME THE WORKER RECEIVED, off the worker side of a real transport ----
    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker within the deadline")
    .expect("the transport delivers it");
    let DispatchFrame::Capsule(capsule) = &frame;
    assert_eq!(
        capsule.placed_on.as_str(),
        WORKER,
        "the send boundary stamps the placement on the capsule arm too, so a refusal at the \
         worker's admission door is attributable"
    );
    assert!(
        capsule.lease_epoch > 0,
        "the delivery clone carries the generation the attempts row records, stamped at delivery"
    );
    assert!(
        capsule.command_id.is_some(),
        "and the durable dispatch command this delivery discharges"
    );

    // THE RECORDED BOUNDS, read off the capsule's own bytes: the shipped `iso`
    // profile authors no `image.memory_mb`, so `declared_memory_bytes`'s
    // `map_or` arm records the node default verbatim — 512 MiB, not a
    // neighbouring power of two — and `pids.max` the assembly default.
    let capsule_bytes = rig
        .cas
        .get(&capsule.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule_body: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&capsule_bytes).expect("the capsule decodes");
    assert_eq!(
        capsule_body.budgets().memory_bytes,
        512 * 1024 * 1024,
        "a stage with no authored memory_mb records the node default"
    );
    assert_eq!(
        capsule_body.budgets().process_count,
        64,
        "the recorded process bound is the assembly default"
    );

    // -- RAW SQLITE: one occurrence, one capsule, one command, and the profile -----
    let conn = raw(&rig.op_path);
    let occurrences: i64 = conn
        .query_row("SELECT count(*) FROM occurrences", [], |row| row.get(0))
        .expect("the occurrences table is readable");
    assert_eq!(occurrences, 1, "exactly ONE occurrence was minted");
    let capsules: i64 = conn
        .query_row("SELECT count(*) FROM capsules", [], |row| row.get(0))
        .expect("the capsules table is readable");
    assert_eq!(capsules, 1, "and exactly ONE capsule was declared");
    let attempts: Vec<Vec<u8>> = {
        let mut statement = conn
            .prepare("SELECT attempt_id FROM attempts")
            .expect("prepare");
        statement
            .query_map([], |row| row.get(0))
            .expect("query")
            .collect::<Result<Vec<Vec<u8>>, _>>()
            .expect("collect")
    };
    assert_eq!(attempts.len(), 1, "and ONE attempt");
    assert_eq!(
        attempts[0],
        capsule.attempt_id.to_bytes().to_vec(),
        "the attempt the plane holds is the one the worker was handed"
    );
    let commands: i64 = conn
        .query_row("SELECT count(*) FROM attempt_commands", [], |row| {
            row.get(0)
        })
        .expect("the attempt_commands table is readable");
    assert_eq!(commands, 1, "and ONE durable dispatch command");

    // THE DISPATCH EVIDENCE: one `dispatched` transition, and the arm the claim
    // stored is the capsule tag on the attempt's blob — there is no profile label
    // left to record because the frame has exactly one arm.
    let dispatched: i64 = conn
        .query_row(
            "SELECT count(*) FROM transitions WHERE kind = 'dispatched'",
            [],
            |row| row.get(0),
        )
        .expect("count dispatched transitions");
    assert_eq!(dispatched, 1, "exactly ONE dispatched transition");
    let arm_tag: &str = conn
        .query_row(
            "SELECT json_extract(assignment_json, '$.capsule') IS NOT NULL FROM attempts \
             WHERE attempt_id = ?1",
            [capsule.attempt_id.to_bytes().as_slice()],
            |row| {
                let is_capsule: bool = row.get(0)?;
                Ok(if is_capsule { "capsule" } else { "not-capsule" })
            },
        )
        .expect("read the attempt's frame tag");
    assert_eq!(
        arm_tag, "capsule",
        "the dispatched attempt's stored frame carries the capsule tag"
    );

    drop(rig.dir);
}

/// THE CAPSULE ARM — a DELIVERED capsule frame is charged to the
/// concrete worker instance: the registered
/// worker's `active_assignment_count` reads 1 while the attempt is live, and
/// the instance fence the charge feeds means a same-id replacement can no
/// longer receive this attempt's frame.
///
/// **Watched red:** before `deliver_capsule_frame` acquired the charge, the
/// counter stayed 0 — a capsule delivery counted nothing and compared no
/// registration instance.
#[tokio::test]
async fn a_delivered_capsule_frame_charges_the_concrete_worker_instance() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = runner(&rig);
    let directive = directive(&rig).await;

    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo charge"),
        )
        .await
        .expect("the capsule dispatches");
    let _frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker within the deadline")
    .expect("the transport delivers it");

    let count = rig
        .supervisor
        .worker_inventory()
        .iter()
        .find(|worker| worker.id == WORKER)
        .map(|worker| worker.active_assignment_count)
        .expect("the rig's worker is registered");
    assert_eq!(
        count, 1,
        "the delivered capsule is charged against the worker's concrete instance"
    );

    drop(rig.dir);
}

/// An AUTHORED `image.memory_mb` is the budget the capsule records — the value
/// hashed into the checked program, never the node default.
///
/// **Would red if:** `declared_memory_bytes` returned the default for a
/// directive that declares one, or scaled the authored value by anything but
/// `1024 * 1024` (the `saturating_mul` arm).
#[tokio::test]
async fn an_authored_memory_mb_is_the_budget_the_capsule_records() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let program = compile_starlark_execution_program(
        "mbyte = stage(\n\
        \x20   id = \"mbyte\",\n\
        \x20   agent = \"shell\",\n\
        \x20   run = \"true\",\n\
        \x20   sandbox = sandbox_profile(image = {\"memory_mb\": 768}),\n\
        \x20   )\n\
         workflow(\"authored-mem\", root = [mbyte])\n",
        "authored-mem.star",
        &[],
    )
    .expect("the authored-memory pack compiles");
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(rig.execution_id, &program)
        .expect("the program is retained");
    seed_scratch_head(&rig);
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("mbyte")))
        .expect("the stage is present");
    let directive = rig
        .dispatcher
        .resolve_sandbox(
            stage.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            rig.execution_id,
            stage.should_confine_to_declared_inputs(),
            stage.is_content_cacheable(),
        )
        .await
        .expect("the profile resolves");
    let runner =
        WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
            .expect("the runner builds")
            .with_cache_store(Arc::clone(&rig.store));

    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new("mbyte"),
            directive,
            &RenderedCommand::rendered("echo authored"),
        )
        .await
        .expect("the capsule submits");

    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame arrives")
    .expect("the transport delivers");
    let DispatchFrame::Capsule(capsule) = &frame;
    let capsule_bytes = rig
        .cas
        .get(&capsule.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule_body: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&capsule_bytes).expect("the capsule decodes");
    assert_eq!(
        capsule_body.budgets().memory_bytes,
        768 * 1024 * 1024,
        "the authored 768 MiB is the budget the capsule records — neither the 512 MiB \
         default nor a neighbouring scale"
    );
}

/// Submit the shipped stage on `rig` and return the refusal text, asserting that NOTHING
/// was written — the environment selection precedes the publish, so every plane table
/// stays empty, read through a second handle.
async fn refused_submit_writes_nothing(rig: Rig) -> String {
    let runner = runner(&rig);
    let directive = directive(&rig).await;
    let refusal = runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect_err("the node's environment is not bindable, so no capsule may be authorized")
        .to_string();
    let conn = raw(&rig.op_path);
    for table in ["occurrences", "capsules", "attempts", "attempt_commands"] {
        let count: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("the table is readable");
        assert_eq!(count, 0, "{table} must be empty after a refused submit");
    }
    drop(rig.dir);
    refusal
}

/// Under `oci` the resolver STAMPS NOTHING and MATERIALIZES NOTHING for a
/// workspace-fs profile: `directive.env` is EMPTY (the capsule binds `/work` by
/// content ref, not a main path), and the
/// `workspaces/<execution>` dir never exists on the filesystem — read raw off
/// the manager's root. The capsule's `/work` remains the recorded head.
#[tokio::test]
async fn a_capsule_submit_maps_the_recorded_head_and_materializes_no_workspace_dir() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = runner(&rig);
    let directive = directive(&rig).await.expect("the shipped profile resolves");
    assert!(
        directive.env.is_empty(),
        "oci stamps no main-host workspace path, and no env at all: {directive:?}"
    );
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            Some(directive),
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("the recorded head is /work; the stripped host path is not consulted");
    let head = rig
        .db
        .execution_work_tree_head(rig.execution_id)
        .expect("the head reads")
        .expect("the rig's admission seed recorded it");
    let mapped: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT work_tree_artifact_id FROM occurrences", [], |row| {
            row.get(0)
        })
        .expect("the occurrence's /work mapping");
    assert_eq!(
        mapped,
        head.work_tree_artifact_id.to_vec(),
        "the capsule's /work is the recorded head, not a walked substitute"
    );
    drop(rig.dir);
}

#[tokio::test]
async fn the_capsule_submit_refuses_by_name_when_boot_bound_no_environment() {
    let rig = rig_with(None);
    // A PROMOTED row exists — so the refusal is about the missing BINDING, and a
    // selection that queried the plane for "the promoted one" would have taken it.
    declare_promoted_environment(&rig);
    let refusal = refused_submit_writes_nothing(rig).await;
    assert!(
        refusal.contains("execution_profile_environment_unbound"),
        "refused by name: {refusal}"
    );
}

#[tokio::test]
async fn the_capsule_submit_refuses_by_name_when_the_bound_environments_row_vanished() {
    let rig = rig();
    // Bound at "boot", and no row: the defensive arm.
    let refusal = refused_submit_writes_nothing(rig).await;
    assert!(
        refusal.contains("execution_profile_environment_absent"),
        "refused by name: {refusal}"
    );
}

#[tokio::test]
async fn the_capsule_submit_refuses_by_name_when_the_bound_environment_is_unpromoted() {
    let rig = rig();
    declare_unpromoted_environment(&rig);
    let refusal = refused_submit_writes_nothing(rig).await;
    assert!(
        refusal.contains("execution_profile_environment_unpromoted"),
        "refused by name, at selection, rather than by the authorization gate: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// A worker's refusal of a capsule attempt is ADJUDICATED
// ---------------------------------------------------------------------------

/// The worker refuses the frame (an absent route, any route
/// refusal), reports a frame-echoed `Failed`, and the attempt reaches a TERMINAL durable
/// state — read as the transition chain's own last word through a second raw handle.
///
/// # What this cell is a regression for
///
/// A failure plan that looked the attempt's dispatch command up in a process-local cache
/// the capsule path never fills would error before any decision was made; the reactor
/// would log and continue, no recovery leg could settle it, and the attempt would stick
/// at `["claimed", "dispatched"]` forever.
#[tokio::test]
async fn a_workers_refusal_of_a_capsule_attempt_reaches_a_terminal_transition() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = runner(&rig);
    let directive = directive(&rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("the capsule submit path authorizes and delivers");
    let DispatchFrame::Capsule(frame) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it");

    // THE WORKER'S OWN REFUSAL: a `Failed` message carrying a route refusal by
    // name — the same string `capsule_route::admit` emits for a host that cannot
    // deliver the rootless-OCI prerequisite — the fence ECHOED off the frame,
    // and the observation that nothing ran.
    let reason =
        "oci_route_uncertified: this node's stages run as capsules in a rootless container, \
         and this host cannot deliver the rootless-OCI prerequisite: a fixture refusal"
            .to_string();
    let reactor = kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(WORKER),
        std::sync::Arc::clone(&rig.worker_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        )),
    );
    reactor
        .handle_message_for_test(kata_transport::types::WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: reason.clone(),
            fence: fence_of(&frame),
            verdict: kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
            provider_failure: None,
            usage: None,
        })
        .expect("the reactor adjudicates a capsule attempt's failure");

    // -- RAW SQLITE: the chain's own last word on this attempt ----------------
    let conn = raw(&rig.op_path);
    // The terminal fold is recorded as the ACCEPTING transition's `resulting_state` — the
    // ingress fence and the adjudication commit together — so the question "did this
    // refusal terminalize the attempt" is asked of that column and not of `kind`.
    let (resulting_state, reason): (String, String) = conn
        .query_row(
            "SELECT resulting_state, json_extract(payload_json, '$.reason') \
               FROM transitions WHERE attempt_id = ?1 ORDER BY seq DESC LIMIT 1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's last transition is readable");
    assert_eq!(
        resulting_state, "failed",
        "the worker's refusal must TERMINALIZE the attempt; a chain stopped at \
         `dispatched` stays there forever"
    );
    assert!(
        reason.contains("oci_route_uncertified"),
        "the RECORDED reason is the worker's own refusal, by name: {reason}"
    );
    let state: String = conn
        .query_row(
            "SELECT state FROM attempt_projection p JOIN attempts a                ON a.execution_id = p.execution_id AND a.stage_id = p.stage_id               AND a.attempt_ordinal = p.attempt_ordinal WHERE a.attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt projection is readable");
    assert_eq!(
        state, "failed",
        "and the projection folds it, so nothing reads this attempt as live"
    );
    let recorded: String = conn
        .query_row(
            "SELECT json_extract(payload_json, '$.delivery.worker_id') FROM transitions \
               WHERE attempt_id = ?1 AND resulting_state = 'failed'",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the terminal transition is readable");
    assert_eq!(
        recorded, WORKER,
        "the failure is attributed to the worker the frame was placed on"
    );
    drop(rig.dir);
}

/// A capsule attempt that FAILS while an operator stop stands against it is recorded as
/// CANCELLED, not failed — the stop is the operator's decision and the failure is its
/// consequence. Read off the chain's last transition through a second raw handle.
#[tokio::test]
async fn a_capsule_failure_under_a_standing_stop_is_recorded_as_cancelled() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = runner(&rig);
    let directive = directive(&rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("the capsule submit path authorizes and delivers");
    let DispatchFrame::Capsule(frame) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it");
    rig.db
        .record_stop_request(
            frame.attempt_id,
            frame.lease_epoch,
            frame.placed_on.as_str(),
            "operator cancelled the execution",
        )
        .expect("the stop is recorded against the dispatched attempt");

    let reactor = kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(WORKER),
        std::sync::Arc::clone(&rig.worker_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        )),
    );
    reactor
        .handle_message_for_test(kata_transport::types::WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: "capsule route refused: the container was killed".to_owned(),
            fence: fence_of(&frame),
            verdict: kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous,
            provider_failure: None,
            usage: None,
        })
        .expect("the reactor adjudicates a capsule attempt's failure under a stop");

    let conn = raw(&rig.op_path);
    let (resulting_state, reason): (String, String) = conn
        .query_row(
            "SELECT resulting_state, json_extract(payload_json, '$.reason') \
               FROM transitions WHERE attempt_id = ?1 ORDER BY seq DESC LIMIT 1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's last transition is readable");
    assert_eq!(
        resulting_state, "cancelled",
        "a failure under a standing operator stop is the stop's outcome: {reason}"
    );
    assert!(
        reason.contains("standing operator stop"),
        "and the recorded reason says so: {reason}"
    );
    drop(rig.dir);
}

/// Submit the shipped stage as a capsule and return the attempt the worker side received.
async fn dispatched_capsule_attempt(rig: &Rig) -> kata_transport::types::CapsuleAssignment {
    declare_promoted_environment(rig);
    let runner = runner(rig);
    let directive = directive(rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("the capsule submit path authorizes and delivers");
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    }
}

/// `(resulting_state, reason)` of an attempt's LAST transition, through a second handle.
fn last_transition(rig: &Rig, attempt: Ulid) -> (String, String) {
    raw(&rig.op_path)
        .query_row(
            "SELECT resulting_state, coalesce(json_extract(payload_json, '$.reason'), '') \
               FROM transitions WHERE attempt_id = ?1 ORDER BY seq DESC LIMIT 1",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's last transition is readable")
}

/// A capsule attempt whose WORKER DIES is settled terminal, PROVEN AMBIGUOUS, and not
/// re-delivered: a re-delivery leg that refused the arm would read the refusal as "not
/// redispatched" and leave the attempt `dispatched` forever.
#[tokio::test]
async fn a_capsule_attempt_on_a_dead_worker_is_settled_ambiguous_not_left_dispatched() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "the premise"
    );
    let settled = rig
        .dispatcher
        .handle_worker_death(
            WORKER,
            &kata_workflow::dispatcher::WorkerLoss::ConnectionClosed("the rig closed it".into()),
        )
        .await
        .expect("the worker-death leg runs");
    assert!(
        settled.contains(&frame.attempt_id),
        "the settlement committed this attempt: {settled:?}"
    );
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "failed", "settled terminal: {reason}");
    assert!(
        reason.contains("PROVEN AMBIGUOUS") && reason.contains(&format!("worker {WORKER} died")),
        "the recorded reason names the cause and the verdict: {reason}"
    );
    // The leg and the worker's process, as the settlement found them: this rig's
    // worker is an in-process transport, whose process is this test's own.
    assert!(
        reason.contains("died: its connection closed (the rig closed it)")
            && reason.contains(&format!(
                "its process {} exists in state ",
                std::process::id()
            )),
        "the recorded reason names the leg and the worker's process: {reason}"
    );
    let commands: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM attempt_commands", [], |row| {
            row.get(0)
        })
        .expect("readable");
    assert_eq!(commands, 1, "and no second dispatch command was enqueued");
    drop(rig.dir);
}

/// The reactor this rig's worker side reports through.
fn reactor(rig: &Rig) -> kata_workflow::reactor::ResultReactor {
    kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(WORKER),
        std::sync::Arc::clone(&rig.worker_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        )),
    )
}

/// The fence a worker echoes on every frame of a capsule attempt — the transport's own
/// encoder, the one `worker_loop` and `capsule_execution` send through.
fn fence_of(
    frame: &kata_transport::types::CapsuleAssignment,
) -> kata_transport::types::AttemptFence {
    kata_transport::types::AttemptFence::echoing_capsule(frame)
}

/// The capsule arm's START checkpoint, through the encoder `worker_loop` sends it with.
fn start_checkpoint(
    frame: &kata_transport::types::CapsuleAssignment,
) -> kata_transport::types::WorkerMessage {
    kata_transport::types::WorkerMessage::Checkpoint(
        kata_transport::types::StageCheckpoint::capsule_started(frame),
    )
}

/// A capsule attempt QUEUED behind a busy worker — dispatched, never started — is NOT
/// settled by the wall-time sweep however late the tick: it is waiting, not late (the
/// review's example settled a queued stage while its container ran). Once the worker's
/// start checkpoint folds `running`, the SAME sweep settles it one millisecond past
/// start + wall + grace and not at it, and sends the worker a FENCED stop.
#[tokio::test]
async fn the_wall_time_sweep_measures_from_start_and_never_settles_a_queued_attempt() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let dispatched_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let wall = i64::try_from(kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS).unwrap();
    let grace = i64::try_from(kata_workflow::dispatcher::CAPSULE_WALL_TIME_GRACE_MS).unwrap();
    // QUEUED BEHIND A BUSY WORKER: another capsule attempt on the same worker has STARTED,
    // so the start-deadline leg exempts this one (its wait is backpressure), and the
    // wall-time leg must not count the wait either. The tick is one millisecond past the
    // deadline a dispatch-anchored wall clock would have had; the sibling STARTED one
    // millisecond before the tick, so its own (thirty-second) wall clock has not elapsed
    // and it is still the started attempt that exempts the queue.
    let busy_execution = Ulid::new();
    let program = shipped_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(busy_execution, &program)
        .unwrap();
    kata_workflow::test_harness::seed_dispatched_capsule_attempt(
        &rig.db,
        &rig.cas,
        busy_execution,
        program.program_hash,
        SHIPPED_STAGE,
        WORKER,
        Some(dispatched_at + wall + grace),
    );
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(u64::try_from(dispatched_at + wall + grace + 1).unwrap())
        .await;
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "a queued (unstarted) attempt is never settled for time spent waiting"
    );

    reactor(&rig)
        .handle_message_for_test(start_checkpoint(&frame))
        .expect("the start checkpoint folds");
    let started_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT started_at_ms FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the start is folded onto the attempt row");
    assert_eq!(last_transition(&rig, frame.attempt_id).0, "running");

    let wall = i64::try_from(kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS).unwrap();
    let grace = i64::try_from(kata_workflow::dispatcher::CAPSULE_WALL_TIME_GRACE_MS).unwrap();
    let deadline = u64::try_from(started_at + wall + grace).unwrap();
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(deadline)
        .await;
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "running",
        "AT the deadline nothing is settled"
    );
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(deadline + 1)
        .await;
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("capsule wall time elapsed") && reason.contains("PROVEN AMBIGUOUS"),
        "{reason}"
    );
    // THE FENCED STOP, off the worker side of the real transport — the busy sibling's own
    // settlement may have sent one first, so read until this attempt's.
    let control = loop {
        let control = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rig.worker_side.recv_control(),
        )
        .await
        .expect("a control frame reaches the worker")
        .expect("the transport delivers it");
        if let kata_transport::types::WorkerControl::Stop { assignment_id, .. } = &control
            && *assignment_id != frame.attempt_id
        {
            continue;
        }
        break control;
    };
    match control {
        kata_transport::types::WorkerControl::Stop {
            assignment_id,
            fence,
            ..
        } => {
            assert_eq!(assignment_id, frame.attempt_id);
            assert_eq!(fence.lease_epoch, frame.lease_epoch);
            assert_eq!(fence.worker_id.as_str(), WORKER);
        }
        other => panic!("the settlement sends a fenced stop, not {other:?}"),
    }
    drop(rig.dir);
}

/// A completion that arrives AFTER the main settled the attempt is SUPERSEDED at the
/// reactor before anything is adopted: no `artifacts` row, no retained root, no new
/// transition.
#[tokio::test]
async fn a_late_capsule_completion_after_settlement_adopts_nothing() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    rig.dispatcher
        .handle_worker_death(
            WORKER,
            &kata_workflow::dispatcher::WorkerLoss::ConnectionClosed("the rig closed it".into()),
        )
        .await
        .expect("the death leg settles it");
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "failed",
        "the premise"
    );
    let counts = |rig: &Rig| -> (i64, i64) {
        raw(&rig.op_path)
            .query_row(
                "SELECT (SELECT count(*) FROM artifacts), (SELECT count(*) FROM transitions)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    };
    let before = counts(&rig);
    // A REAL result tree, published, so adoption WOULD succeed if it were attempted.
    let member = rig.cas.put_durable(b"late result\n").unwrap();
    let manifest =
        kata_types::tree_artifact::TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new("late.txt").unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        }])
        .unwrap();
    let durable = rig
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    reactor(&rig)
        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: fence_of(&frame),
            result: kata_types::execution_contract::ArtifactRef::new(
                durable.object_id(),
                durable.size(),
                kata_types::execution_contract::ArtifactPrivacy::Private,
            ),
            work_delta: None,
            exit_code: Some(0),
            stdout: publish_capture(&rig, b""),
            stderr: publish_capture(&rig, b""),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "late",
            ),
            egress_refusals: vec![],
        })
        .expect("a superseded completion is not an error");
    assert_eq!(counts(&rig), before, "nothing adopted, nothing recorded");
    // NO BYTE OF A SUPERSEDED RESULT IS READ: a late frame naming a manifest this node's
    // store does not hold is still answered `Ok` with nothing recorded, because the
    // reactor's early terminal check returns before adoption reads anything. Without that
    // check the adoption's verified read refuses it, which is an error out of the arm.
    let absent = kata_types::cache::object_id_for_canonical_bytes(b"a manifest never published");
    // AND IT LEAVES A TRACE: the drop is counted, labelled where it happened.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let late_reactor = reactor(&rig);
    metrics::with_local_recorder(&recorder, || {
        late_reactor.handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: fence_of(&frame),
            result: kata_types::execution_contract::ArtifactRef::new(
                absent,
                26,
                kata_types::execution_contract::ArtifactPrivacy::Private,
            ),
            work_delta: None,
            exit_code: Some(0),
            stdout: publish_capture(&rig, b""),
            stderr: publish_capture(&rig, b""),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "late",
            ),
            egress_refusals: vec![],
        })
    })
    .expect("a superseded completion reads nothing, so it cannot be refused");
    assert_eq!(counts(&rig), before, "and records nothing");
    let dropped: Vec<u64> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| {
            key.key().name() == "kata_capsule_completion_superseded_total"
                && key
                    .key()
                    .labels()
                    .any(|label| label.key() == "dropped_at" && label.value() == "terminal")
        })
        .filter_map(|(_, _, _, value)| match value {
            metrics_util::debugging::DebugValue::Counter(count) => Some(count),
            _ => None,
        })
        .collect();
    assert_eq!(dropped, vec![1], "the dropped completion is counted once");
    drop(rig.dir);
}

/// THE DIVERT'S OWN CONDITION, host-free: a runner driven through `run()` on an `oci`-profile
/// dispatcher reaches the capsule submit path and refuses with ITS refusal — so the `if` in
/// `submit_stage` is exercised rather than described.
///
/// The refusal it stops on is the capsule path's environment selection, and that is the
/// point: only the capsule path refuses this way.
#[tokio::test]
async fn the_divert_condition_routes_a_shell_stage_into_the_capsule_path() {
    let rig = rig();
    // NOTHING is declared. The capsule path walks the (empty) workspace and then selects the
    // boot-bound environment, whose row this rig never wrote, so that is the refusal — and
    // reaching it at all is what proves the divert was taken.
    let runner = runner(&rig);
    let error = runner
        .run()
        .await
        .expect_err("an oci node with an empty plane authorizes no capsule");
    let message = error.to_string();
    assert!(
        message.contains("execution_profile_environment_absent"),
        "the divert must have been TAKEN — only the capsule path refuses with \
         execution_profile_environment_absent: {message}"
    );
    // And nothing went out: no attempt row at all, read through a second handle.
    let conn = raw(&rig.op_path);
    let attempts: i64 = conn
        .query_row("SELECT count(*) FROM attempts", [], |row| row.get(0))
        .expect("readable");
    assert_eq!(
        attempts, 0,
        "the profile refuses BEFORE any attempt is claimed, on either arm"
    );
    drop(rig.dir);
}

/// THE DEATH LEG'S PLACEMENT FENCE, driven directly: a settlement addressed to a worker
/// the attempt is NOT placed on (the victim scan and the settlement are not atomic, and
/// the attempt may have moved) settles nothing.
#[tokio::test]
async fn a_settlement_for_a_worker_the_attempt_is_not_placed_on_settles_nothing() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let settled = rig
        .dispatcher
        .settle_lost_capsule_attempt_for_test(frame.attempt_id, "worker other died", Some("other"))
        .await
        .expect("the settlement runs");
    assert!(!settled);
    assert_eq!(last_transition(&rig, frame.attempt_id).0, "dispatched");
    assert!(
        rig.dispatcher
            .settle_lost_capsule_attempt_for_test(frame.attempt_id, "worker died", Some(WORKER))
            .await
            .expect("the settlement runs"),
        "and the placed worker's settlement does settle it"
    );
    drop(rig.dir);
}

/// THE HEAD BINDS THE OCCURRENCE: a capsule mapping an execution-retained tree
/// that is NOT the recorded `/work` head is refused as this attempt's `/work`,
/// even though its content is a real declared tree.
#[tokio::test]
async fn a_work_tree_that_is_not_the_recorded_head_is_refused() {
    let rig = rig();
    declare_promoted_environment(&rig);
    // Admission by hand — not `runner()`, which would seed a head of ITS OWN and
    // leave the explicit seed below the divergent second input.
    let program = shipped_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(rig.execution_id, &program)
        .expect("the program is retained");
    let lowered = kata_program::execution_program::lower_stage_operation(
        &program,
        &StageId(SmolStr::new(SHIPPED_STAGE)),
    )
    .unwrap();
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(rig.execution_id),
        program.program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    // THE RECORDED HEAD: the production seed verb over a real scratch dir.
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("a.txt"), b"x").unwrap();
    let head = kata_core::work_tree::publish_scratch_tree_head(
        &rig.db,
        &rig.cas,
        rig.execution_id,
        workspace.path(),
    )
    .unwrap();
    // A foreign tree: real, declared, retained by the execution — and NOT the head.
    let foreign_member = rig.cas.put_durable(b"not the head\n").unwrap();
    let foreign_manifest =
        kata_types::tree_artifact::TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new("other.txt").unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: foreign_member.object_id(),
                size_bytes: foreign_member.size(),
            },
        }])
        .unwrap();
    let foreign_durable = rig
        .cas
        .put_durable(&foreign_manifest.manifest_bytes().unwrap())
        .unwrap();
    let foreign = kata_core::work_tree::declare_work_tree(
        &rig.db,
        &rig.cas,
        rig.execution_id,
        &foreign_manifest,
        &foreign_durable,
    )
    .unwrap();
    kata_core::work_tree::declare_empty_tree(&rig.db, &rig.cas, rig.execution_id).unwrap();
    let directive = directive(&rig).await.unwrap();
    let stripped = directive.clone();
    let (prepared, capsule) = kata_workflow::capsule_assembly::assemble_capsule(
        &lowered,
        occurrence.id(),
        program
            .stages
            .get(&StageId(SmolStr::new(SHIPPED_STAGE)))
            .unwrap(),
        &stripped,
        &RenderedCommand::rendered("echo cutover"),
        EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
        boot_binding().platform,
        foreign.id(),
        kata_workflow::capsule_assembly::NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .unwrap();
    let refusal = kata_workflow::authorization::authorize_attempt(
        &rig.db,
        &rig.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(rig.execution_id),
            program_hash: program.program_hash,
            lowered: &lowered,
            occurrence,
            prepared,
            capsule,
            environment: EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
            work_head: Some(&head),
            programs: &kata_workflow::test_harness::FixtureProgramProbe(vec!["sh"]),
            checked_stage: program
                .stages
                .get(&StageId(SmolStr::new(SHIPPED_STAGE)))
                .expect("the shipped stage"),
            place: &|| Ok(WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .expect_err("a tree that is not the recorded head is not this attempt's /work")
    .to_string();
    assert!(
        refusal.contains(kata_workflow::authorization::WORK_TREE_NOT_ROLE_BOUND),
        "refused by name: {refusal}"
    );
    drop(rig.dir);
}

/// Publish `bytes` as one capture blob in the rig's CAS — the shape a v6 frame's
/// `stdout`/`stderr` carry (the provider spools, the worker publishes, the wire
/// holds a reference).
fn publish_capture(rig: &Rig, bytes: &[u8]) -> kata_types::execution_contract::ArtifactRef {
    let receipt = rig.cas.put_durable(bytes).unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    )
}

/// The `/work` delta a stub worker reports for `frame`'s capsule.
fn stub_work_delta(
    rig: &Rig,
    frame: &kata_transport::types::CapsuleAssignment,
) -> Option<kata_types::execution_contract::ArtifactRef> {
    kata_workflow::test_harness::stub_work_delta(&rig.db, &rig.cas, frame.occurrence_id)
}

/// A `CompletedCapsule` naming `result` for `frame`'s generation.
fn completed_capsule(
    rig: &Rig,
    frame: &kata_transport::types::CapsuleAssignment,
    result: kata_types::execution_contract::ArtifactRef,
) -> kata_transport::types::WorkerMessage {
    // The capture refs name real blobs: a completion is verified before
    // adoption, and a ref naming an object this node never published refuses.
    kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id: frame.attempt_id,
        fence: fence_of(frame),
        result,
        work_delta: stub_work_delta(rig, frame),
        exit_code: Some(0),
        stdout: publish_capture(rig, b""),
        stderr: publish_capture(rig, b""),
        capture_exceeded: false,
        agent: None,
        provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
            "cell",
        ),
        egress_refusals: vec![],
    }
}

/// A result the main's adoption REFUSES is RECORDED as the attempt's outcome — failed,
/// PROVEN AMBIGUOUS, the refusal as the reason — and the error still leaves the arm.
///
/// Before: the refusal was returned out of the reactor arm and only logged, and the
/// attempt stayed `dispatched` until some sweep reached it (none reaches an unstarted
/// one). Here the refused result is a manifest this node's store does not hold.
#[tokio::test]
async fn a_refused_capsule_result_is_recorded_failed_ambiguous() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let absent = kata_types::cache::object_id_for_canonical_bytes(b"never published");
    let error = reactor(&rig)
        .handle_message_for_test(completed_capsule(
            &rig,
            &frame,
            kata_types::execution_contract::ArtifactRef::new(
                absent,
                15,
                kata_types::execution_contract::ArtifactPrivacy::Private,
            ),
        ))
        .expect_err("the refusal still leaves the arm, so the loop logs it")
        .to_string();
    assert!(error.contains("capsule result refused"), "{error}");
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(
        state, "failed",
        "the refusal is the attempt's recorded outcome: {reason}"
    );
    assert!(
        reason.contains("refused the capsule's reported result")
            && reason.contains("PROVEN AMBIGUOUS")
            && reason.contains("capsule result refused"),
        "the recorded reason is the refusal and the verdict: {reason}"
    );
    let artifacts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(artifacts, 0, "and nothing was accepted");
    drop(rig.dir);
}

/// A reported result whose MANIFEST is over the tree ceiling is refused on its CLAIMED
/// LENGTH, by the adoption's manifest ceiling CAPPED at the tree ceiling — and recorded
/// as the attempt's outcome; nothing is declared or accepted. The manifest is real:
/// 18 000 entries with long paths over one member the store holds (about 72 MB, past the
/// 64 MiB tree ceiling), encoded with `serde_json` directly (the tree encoder refuses
/// to produce it), published into the node's store.
///
/// A 10 000-entry promise makes the entry-derived arm of `manifest_ceiling` — about
/// 44 MiB — the binding term, which would refuse this manifest BEFORE the tree cap
/// could bind. So the occurrence's capsule is re-minted promising 20 000 entries,
/// where `20 000 × MAXIMUM_ENTRY_ENCODING_BYTES + 1024` exceeds the tree ceiling and
/// `.min(TreeManifest::MAXIMUM_ENCODED_BYTES)` is the term that fires: the new capsule
/// is a REAL capsule (`Capsule::new`, id folded over the raised promise), published,
/// given its own `capsules` row, and bound to the attempt's occurrence through the same
/// columns the adoption reads.
///
/// **Would red if:** `manifest_ceiling` were not capped at
/// `TreeManifest::MAXIMUM_ENCODED_BYTES` — the review measured such a result adopted and
/// accepted, and the collection root loader then failing closed on it.
#[tokio::test]
async fn a_result_manifest_over_the_tree_ceiling_is_refused_on_its_claimed_length() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let member = rig.cas.put_durable(b"").unwrap();
    // Re-mint the occurrence's capsule with a 20 000-entry promise so the manifest
    // ceiling IS the tree cap: the shipped stage's 10 000-entry promise derives about
    // 44 MiB, under the cap, and would be the refusing term instead.
    {
        let writer = rusqlite::Connection::open(&rig.op_path).unwrap();
        let occurrence = frame.occurrence_id.0.0.to_vec();
        let (capsule_id, object_id): (Vec<u8>, Vec<u8>) = writer
            .query_row(
                "SELECT c.capsule_id, c.capsule_object_id \
                   FROM occurrences o JOIN capsules c ON c.capsule_id = o.capsule_id \
                  WHERE o.occurrence_id = ?1",
                [&occurrence],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the dispatched occurrence names its capsule row");
        let object: kata_types::primitives::ObjectId =
            kata_types::primitives::FixedBytes(object_id.try_into().unwrap());
        let bytes = rig
            .cas
            .get_verified_bounded(
                &object,
                kata_types::execution_contract::Capsule::MAXIMUM_ENCODED_BYTES,
            )
            .expect("the authorized capsule's bytes are in the bound store");
        let capsule: kata_types::execution_contract::Capsule =
            serde_json::from_slice(&bytes).expect("the bytes decode as a capsule");
        assert_eq!(capsule.budgets().result_entries, 10_000, "the premise");
        let reminted = kata_types::execution_contract::Capsule::new(
            capsule.occurrence(),
            capsule.action(),
            capsule.environment(),
            capsule.platform(),
            capsule.inputs().to_vec(),
            capsule.process().clone(),
            capsule.network().clone(),
            None,
            kata_types::execution_contract::CapsuleBudgets {
                result_entries: 20_000,
                ..capsule.budgets()
            },
            None,
        )
        .expect("a capsule promising 20 000 result entries is constructible");
        let reminted_object = rig
            .cas
            .put_durable(&serde_json::to_vec(&reminted).unwrap())
            .expect("the re-minted capsule publishes");
        writer
            .execute(
                "INSERT INTO capsules (capsule_id, occurrence_id, prepared_action_id, \
                                       environment_id, platform_id, capsule_object_id, \
                                       created_at_ms) \
                 SELECT ?1, occurrence_id, prepared_action_id, environment_id, platform_id, \
                        ?2, created_at_ms FROM capsules WHERE capsule_id = ?3",
                rusqlite::params![
                    reminted.id().0.0.as_slice(),
                    reminted_object.object_id().0.as_slice(),
                    capsule_id.as_slice(),
                ],
            )
            .expect("the re-minted capsule gets its own row");
        writer
            .execute(
                "UPDATE occurrences SET capsule_id = ?1 WHERE occurrence_id = ?2",
                rusqlite::params![reminted.id().0.0.as_slice(), occurrence.as_slice()],
            )
            .expect("the occurrence now names the raised-promise capsule");
    }
    // ~4 KB of path per entry × 18 000 ≈ 72 MB — over the 64 MiB encoding
    // ceiling on the CLAIMED length alone, which is the door under test.
    let entries = (0..18_000u32)
        .map(|index| kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new(format!(
                "d/{index:05}{}",
                "f".repeat(3_750)
            ))
            .unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        })
        .collect();
    let manifest = kata_types::tree_artifact::TreeManifest::new(entries).unwrap();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let ceiling = kata_types::tree_artifact::TreeManifest::MAXIMUM_ENCODED_BYTES;
    assert!(
        bytes.len() as u64 > ceiling,
        "the premise: {} bytes",
        bytes.len()
    );
    let durable = rig.cas.put_durable(&bytes).unwrap();
    let error = reactor(&rig)
        .handle_message_for_test(completed_capsule(
            &rig,
            &frame,
            kata_types::execution_contract::ArtifactRef::new(
                durable.object_id(),
                durable.size(),
                kata_types::execution_contract::ArtifactPrivacy::Private,
            ),
        ))
        .expect_err("the refusal still leaves the arm")
        .to_string();
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(
        state, "failed",
        "the refusal is the recorded outcome: {reason}"
    );
    assert!(
        reason.contains(&format!("over the manifest ceiling {ceiling}")),
        "refused by the capped ceiling on the claimed length, before the bytes are read: \
         {reason} / {error}"
    );
    let conn = raw(&rig.op_path);
    let declared: i64 = conn
        .query_row(
            "SELECT count(*) FROM artifacts WHERE object_id = ?1",
            [durable.object_id().0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(declared, 0, "no artifacts row names the refused manifest");
    let accepted: i64 = conn
        .query_row(
            "SELECT count(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted, 0, "and nothing was accepted");
    drop(rig.dir);
}

/// SETTLEMENT FIRST, THEN THE COMPLETION: the accepting door re-reads the fence under the
/// writer lock and declares NOTHING — no `artifacts` row for the result, no acceptance —
/// even though the reactor's early check is bypassed by the settlement committing after
/// it. Driven here by settling between the early check's view and the door, which is the
/// order a racing sweep produces: the door is called with the attempt already terminal.
#[tokio::test]
async fn a_completion_that_loses_to_a_settlement_declares_nothing() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let kata_core::operational::AttemptArm::Capsule(occurrence) = rig
        .db
        .recovered_attempt(frame.attempt_id)
        .unwrap()
        .expect("the attempt row")
        .arm()
        .unwrap()
    else {
        panic!("a bound capsule attempt");
    };
    let member = rig.cas.put_durable(b"raced result\n").unwrap();
    let manifest =
        kata_types::tree_artifact::TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new("raced.txt").unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        }])
        .unwrap();
    let durable = rig
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let result = kata_types::execution_contract::ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    );
    rig.dispatcher
        .settle_lost_capsule_attempt_for_test(frame.attempt_id, "a racing sweep", None)
        .await
        .expect("the settlement records");
    let artifacts_before: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))
        .unwrap();
    let attempt = rig.db.attempt(frame.attempt_id).unwrap().unwrap();
    let (_, verdict) = rig
        .db
        .adopt_and_accept_capsule_completion(
            &kata_core::operational::CapsuleResultAdoption {
                execution_id: attempt.execution_id,
                occurrence_id: occurrence,
                result: result.clone(),
                stdout: publish_capture(&rig, b"the stdout bytes"),
                stderr: publish_capture(&rig, b""),
                work_delta: stub_work_delta(&rig, &frame),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id: attempt.execution_id,
                attempt_id: frame.attempt_id,
                attempt_ordinal: attempt.attempt_ordinal,
                lease_epoch: frame.lease_epoch,
                worker_id: WORKER.to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &publish_capture(&rig, b"the stdout bytes"),
                    &publish_capture(&rig, b""),
                    false,
                    None,
                ),
            },
        )
        .expect("losing the race is an answer, not an error");
    assert_eq!(
        verdict,
        kata_core::operational::CompletionVerdict::Superseded
    );
    let artifacts_after: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        artifacts_after, artifacts_before,
        "the result is declared only by the transaction that accepts it"
    );
    assert_eq!(last_transition(&rig, frame.attempt_id).0, "failed");
    drop(rig.dir);
}

/// A capsule frame the transport REFUSES is settled PROVEN NOT PERFORMED at the delivery
/// door — no worker holds it, no start will come, and there is no re-delivery.
#[tokio::test]
async fn an_undelivered_capsule_frame_is_settled_not_performed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let rig = rig_over(Some(dir), &path, Some(boot_binding()), false);
    declare_promoted_environment(&rig);
    let runner = runner(&rig);
    let directive = directive(&rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect_err("the send fails");
    let attempt: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .expect("the attempt was authorized before the send");
    let attempt = Ulid::from_bytes(attempt.try_into().unwrap());
    let (state, reason) = last_transition(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("was not delivered") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    drop(rig.dir);
}

/// A main-side transport whose send never completes — a worker that stopped draining
/// its connection, so the write parks on a full socket. Records whether the send was
/// ENTERED and whether its future was DROPPED: a cancelled write is `entered && dropped`.
#[derive(Default)]
struct NeverTakesTheFrame {
    entered: std::sync::atomic::AtomicBool,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

struct DroppedFlag(Arc<std::sync::atomic::AtomicBool>);

impl Drop for DroppedFlag {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl kata_transport::transport::WorkerTransport for NeverTakesTheFrame {
    async fn dispatch(
        &self,
        _frame: kata_transport::types::CheckedDispatchFrame,
    ) -> kata_types::error::KataResult<()> {
        self.entered
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _flag = DroppedFlag(Arc::clone(&self.dropped));
        std::future::pending::<()>().await;
        unreachable!("the peer never drains")
    }
    async fn send_control(
        &self,
        _control: kata_transport::types::WorkerControl,
    ) -> kata_types::error::KataResult<()> {
        Ok(())
    }
    async fn recv(&self) -> kata_types::error::KataResult<kata_transport::types::WorkerMessage> {
        std::future::pending().await
    }
    async fn shutdown(&self) -> kata_types::error::KataResult<()> {
        Ok(())
    }
    fn is_alive(&self) -> bool {
        true
    }
    fn peer_pid(&self) -> Option<u32> {
        None
    }
    fn kind(&self) -> &'static str {
        "never_takes_the_frame"
    }
}

/// `workers.dispatch_deadline_ms` BOUNDS the capsule send: a worker that holds no started
/// attempt and whose transport never takes the frame does not park the delivery door past
/// it. The write is NOT cancelled —
/// dropping a half-written frame desyncs the connection — so the frame may still reach the
/// worker, and the attempt is settled PROVEN AMBIGUOUS, never PROVEN NOT PERFORMED.
#[tokio::test]
async fn a_worker_that_never_takes_the_frame_does_not_park_dispatch_past_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let wedged = Arc::new(NeverTakesTheFrame::default());
    let rig = rig_assembled(
        Some(dir),
        &path,
        Some(boot_binding()),
        RigTransport::Custom(wedged.clone()),
        kata_workflow::test_harness::rig_worker_containment(),
        Some(std::time::Duration::from_millis(300)),
    );
    declare_promoted_environment(&rig);
    let runner = runner(&rig);
    let directive = directive(&rig).await;
    // Generous on purpose: the wedged send never completes, so any finite outer
    // bound tells the 300 ms dispatch deadline (the property) from a parked door;
    // the slack absorbs the attempt's FULL-sync commits on a loaded host.
    let submitted = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        runner.submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo wedged"),
        ),
    )
    .await
    .expect("the delivery door answers on the dispatch deadline, not on the wedged send");
    submitted.expect_err("an unconfirmed send is not a delivery");
    assert!(
        wedged.entered.load(std::sync::atomic::Ordering::SeqCst),
        "the send was attempted; a refusal before the write proves nothing about the bound"
    );
    assert!(
        !wedged.dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the write future must not be dropped: cancelling a half-written frame desyncs the \
         connection"
    );
    let attempt: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .expect("the attempt was authorized before the send");
    let attempt = Ulid::from_bytes(attempt.try_into().unwrap());
    let (state, reason) = last_transition(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("dispatch_deadline_ms")
            && reason.contains("PROVEN AMBIGUOUS")
            && !reason.contains("NOT PERFORMED"),
        "{reason}"
    );
    drop(rig.dir);
}

/// A worker that is RUNNING an attempt takes its next frame only when that attempt ends,
/// so a send parked behind it is backpressure, not a stall: past
/// `workers.dispatch_deadline_ms` the delivery door still answers, but the attempt stays
/// `dispatched` with its write still pending, and nothing is settled.
#[tokio::test]
async fn a_send_queued_behind_a_running_attempt_is_not_settled_at_the_dispatch_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let wedged = Arc::new(NeverTakesTheFrame::default());
    let rig = rig_assembled(
        Some(dir),
        &path,
        Some(boot_binding()),
        RigTransport::Custom(wedged.clone()),
        kata_workflow::test_harness::rig_worker_containment(),
        Some(std::time::Duration::from_millis(300)),
    );
    declare_promoted_environment(&rig);
    // The worker's one slot is held by a started attempt.
    let program = shipped_program();
    let running_execution = Ulid::new();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(running_execution, &program)
        .unwrap();
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let running = kata_workflow::test_harness::seed_dispatched_capsule_attempt(
        &rig.db,
        &rig.cas,
        running_execution,
        program.program_hash,
        SHIPPED_STAGE,
        WORKER,
        Some(now_ms),
    );
    let runner = runner(&rig);
    let directive = directive(&rig).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        runner.submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo queued"),
        ),
    )
    .await
    .expect("the delivery door answers on the dispatch deadline, not on the parked send")
    .expect("a send queued behind a running attempt is not a failed delivery");
    assert!(
        wedged.entered.load(std::sync::atomic::Ordering::SeqCst),
        "the send was attempted"
    );
    assert!(
        !wedged.dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the queued write stays pending: cancelling it would desync the connection"
    );
    let queued: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT attempt_id FROM attempts WHERE attempt_id != ?1",
            [running.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the queued attempt was authorized before the send");
    let queued = Ulid::from_bytes(queued.try_into().unwrap());
    let (state, reason) = last_transition(&rig, queued);
    assert_eq!(state, "dispatched", "{reason}");
    drop(rig.dir);
}

/// A capsule DELIVERED and never STARTED is settled by the main's start-deadline leg once
/// the node's start deadline plus the grace has passed — and not a millisecond before,
/// and never while the worker holds a started attempt.
#[tokio::test]
async fn a_delivered_capsule_that_never_starts_is_settled_by_the_start_deadline() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let dispatched_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    // `Dispatcher::new`'s default start deadline: fifteen minutes.
    let deadline = u64::try_from(dispatched_at).unwrap()
        + 15 * 60 * 1000
        + kata_workflow::dispatcher::CAPSULE_START_GRACE_MS;
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(deadline)
        .await;
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "AT the deadline nothing is settled"
    );
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(deadline + 1)
        .await;
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("did not start within assignment_start_deadline_ms")
            && reason.contains("PROVEN AMBIGUOUS"),
        "{reason}"
    );
    drop(rig.dir);
}

/// Capsule placement requires a worker claiming CERTIFIED containment: a worker
/// that claims it cannot contain is refused `no_oci_worker_available`, naming
/// what it claimed, with no occurrence, capsule, attempt or command written.
#[tokio::test]
async fn a_capsule_is_never_placed_on_a_worker_without_certified_containment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let rig = rig_over_with_containment(
        Some(dir),
        &path,
        Some(boot_binding()),
        true,
        kata_types::containment_claim::ClaimedContainment::Unavailable {
            evidence: "rig: cannot build a container".into(),
        },
    );
    declare_promoted_environment(&rig);
    let refusal = refused_submit_writes_nothing(rig).await;
    assert!(
        refusal.contains(kata_workflow::dispatcher::NO_OCI_WORKER_AVAILABLE)
            && refusal.contains("certified containment"),
        "{refusal}"
    );
}

/// The CHILD of the dispatch-boundary crash cell: authorize and dispatch one capsule, then
/// die at `after_capsule_dispatched_before_send` — the placement is durable and no frame
/// was sent.
const DISPATCH_CRASH_CHILD: &str = "KATA_CUTOVER_DISPATCH_CRASH_CHILD";
const DISPATCH_CRASH_DIR: &str = "KATA_CUTOVER_DISPATCH_CRASH_DIR";
const DISPATCH_CRASH_CELL: &str =
    "a_crash_between_the_capsule_placement_and_its_send_is_settled_at_restart";

/// THE CAPSULE ARM'S DISPATCH BOUNDARY: a main that dies after the placement commits and
/// before the frame is sent leaves an attempt `dispatched` that no worker holds. The next
/// main's restart settlement records it PROVEN AMBIGUOUS — the plane cannot tell this
/// window from a frame that left just before the death — and nothing re-delivers it.
/// Driven by a real abort in a child process at the registered boundary; read back
/// through a raw handle.
#[tokio::test]
async fn a_crash_between_the_capsule_placement_and_its_send_is_settled_at_restart() {
    if let Some(dir) = std::env::var_os(DISPATCH_CRASH_DIR)
        && std::env::var_os(DISPATCH_CRASH_CHILD).is_some()
    {
        let path = std::path::PathBuf::from(dir);
        let rig = rig_over(None, &path, Some(boot_binding()), true);
        declare_promoted_environment(&rig);
        let runner = runner(&rig);
        let directive = directive(&rig).await;
        let _ = runner
            .submit_stage_as_capsule_for_test(
                &SmolStr::new(SHIPPED_STAGE),
                directive,
                &RenderedCommand::rendered("echo cutover"),
            )
            .await;
        unreachable!("the armed boundary aborts before the send returns");
    }
    assert!(
        kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES
            .iter()
            .any(|boundary| boundary.name == "after_capsule_dispatched_before_send"),
        "the boundary is registered"
    );
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", DISPATCH_CRASH_CELL, "--nocapture"])
        .env(DISPATCH_CRASH_CHILD, "1")
        .env(DISPATCH_CRASH_DIR, dir.path())
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_capsule_dispatched_before_send",
        )
        .status()
        .expect("the armed child runs");
    assert!(
        status.code().is_none(),
        "the child must die on the boundary's abort, not exit: {status:?}"
    );
    let conn = raw(&dir.path().join("operational.db"));
    let (attempt, state): (Vec<u8>, String) = conn
        .query_row(
            "SELECT a.attempt_id, p.state FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("exactly one attempt");
    assert_eq!(state, "dispatched", "the window: placed, never sent");
    drop(conn);
    let attempt = Ulid::from_bytes(attempt.try_into().unwrap());

    // THE NEXT MAIN, over the data directory the crash left.
    let path = dir.path().to_path_buf();
    let rig = rig_over(None, &path, Some(boot_binding()), true);
    assert_eq!(
        rig.dispatcher
            .settle_capsule_attempts_after_restart()
            .expect("the restart leg runs"),
        vec![attempt]
    );
    let (state, reason) = last_transition(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains(kata_workflow::dispatcher::CAPSULE_MAIN_RESTARTED)
            && reason.contains("PROVEN AMBIGUOUS"),
        "{reason}"
    );
    let attempts: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 1, "no second generation was minted");
    drop(rig);
    drop(dir);
}

/// A frame the delivery door cannot BUILD after the placement committed — here the stamp
/// read fails on a malformed durable command row at the attempt's epoch — is settled
/// PROVEN NOT PERFORMED, not returned with the attempt left `dispatched` for no leg.
///
/// **Would red if:** `deliver_capsule_frame` propagated a `frame_for_dispatch` (or
/// checked-frame) error with `?` again.
#[tokio::test]
async fn a_frame_the_delivery_door_cannot_build_is_settled_not_performed() {
    let rig = rig();
    let execution = Ulid::new();
    let program = shipped_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(execution, &program)
        .unwrap();
    let attempt = kata_workflow::test_harness::seed_dispatched_capsule_attempt(
        &rig.db,
        &rig.cas,
        execution,
        program.program_hash,
        SHIPPED_STAGE,
        WORKER,
        None,
    );
    // A command row at the attempt's epoch whose id is not a ULID, newer than the real
    // one, so the stamp read decodes it and fails.
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
    let (state, reason) = last_transition(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("was not delivered") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    drop(rig.dir);
}

/// A dispatched capsule attempt whose STORED frame does not decode — the arm is still
/// recognisably the capsule one, its body is not a frame — is settled PROVEN NOT PERFORMED
/// at the delivery door, and nothing reaches the worker. Honest because the door sends only
/// the frame it decoded: a blob that does not decode has no bytes to send.
///
/// **Would red if:** `deliver_capsule_frame` returned the decode error with `?` again (the
/// attempt would stay `dispatched`, a state no leg settles before the start deadline).
#[tokio::test]
async fn a_stored_frame_that_does_not_decode_is_settled_not_performed() {
    let rig = rig();
    let execution = Ulid::new();
    let program = shipped_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(execution, &program)
        .unwrap();
    let attempt = kata_workflow::test_harness::seed_dispatched_capsule_attempt(
        &rig.db,
        &rig.cas,
        execution,
        program.program_hash,
        SHIPPED_STAGE,
        WORKER,
        None,
    );
    // Keep the arm's single key (so the row still classifies as a capsule attempt) and
    // replace its body with one no `DispatchFrame` decodes, through a second handle.
    let writer = rusqlite::Connection::open(&rig.op_path).unwrap();
    let stored: Vec<u8> = writer
        .query_row(
            "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    let arm = stored
        .as_object()
        .and_then(|object| object.keys().next().cloned())
        .expect("a single-key frame object");
    let planted = serde_json::to_vec(&serde_json::json!({ arm: { "not_a_frame": 42 } })).unwrap();
    writer
        .execute(
            "UPDATE attempts SET assignment_json = ?1 WHERE attempt_id = ?2",
            rusqlite::params![planted, attempt.to_bytes().as_slice()],
        )
        .unwrap();
    let error = rig
        .dispatcher
        .deliver_capsule_frame(attempt)
        .await
        .expect_err("the stored frame does not decode");
    assert!(error.to_string().contains("does not decode"), "{error}");
    let (state, reason) = last_transition(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("does not decode") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(300),
            rig.worker_side.recv_frame()
        )
        .await
        .is_err(),
        "nothing reached the worker"
    );
    drop(rig.dir);
}

/// A capsule attempt CLAIMED and never dispatched is settled PROVEN NOT PERFORMED by the
/// deadline tick once its execution has LATCHED its outcome — and only then: a claim of a
/// running execution is the occurrence boundary's to adopt and is left alone. Until it is
/// settled the claim pins its Nix environment, so `release_environment` is the observable
/// read here, beside the attempt's own chain.
///
/// **Would red if:** no leg settled an abandoned claim (it stays `pending` and the release
/// refuses `environment_bound_to_live_attempt` forever), or the leg settled a claim whose
/// execution can still resume (the running execution's claim would turn `failed`).
#[tokio::test]
async fn an_abandoned_capsule_claim_is_settled_not_performed_and_releases_its_environment() {
    let rig = rig();
    let program = shipped_program();
    let face = rig.dispatcher.execution_lifecycle();
    let (abandoned_execution, running_execution) = (Ulid::new(), Ulid::new());
    for execution in [abandoned_execution, running_execution] {
        face.put_current_program(execution, &program).unwrap();
    }
    let (abandoned, _) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
        &rig.db,
        &rig.cas,
        abandoned_execution,
        program.program_hash,
        SHIPPED_STAGE,
    );
    let (resumable, _) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
        &rig.db,
        &rig.cas,
        running_execution,
        program.program_hash,
        SHIPPED_STAGE,
    );
    face.mark_terminal(
        abandoned_execution,
        kata_workflow::execution_program_store::ExecutionLifecycleState::Failed,
    )
    .expect("the execution terminalizes with its claim still live");
    // The seed declares its environment STAGED; promote it, as boot does, so the release
    // below refuses on a live attempt or not at all.
    let seeded_environment = [0x5E; 32];
    rig.db
        .promote_environment_root(seeded_environment, chrono::Utc::now().timestamp_millis())
        .expect("the seeded environment's gc root promotes");

    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    rig.dispatcher.run_deadline_sweep_tick_for_test(now).await;

    let (state, reason) = last_transition(&rig, abandoned);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("claimed and never dispatched")
            && reason.contains("latched its outcome (failed)")
            && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    let (state, reason) = last_transition(&rig, resumable);
    assert_eq!(
        state, "pending",
        "a running execution's claim is the occurrence recovery's to adopt: {reason}"
    );
    let release = rig
        .db
        .release_environment(seeded_environment, i64::MAX / 4)
        .map_err(|error| error.to_string());
    assert!(
        release
            .as_ref()
            .is_err_and(|refusal| refusal.contains("environment_bound_to_live_attempt")),
        "the resumable claim still binds the environment: {release:?}"
    );

    // Once ITS execution latches too, the same tick settles it and nothing binds the
    // environment any more.
    face.mark_terminal(
        running_execution,
        kata_workflow::execution_program_store::ExecutionLifecycleState::Cancelled,
    )
    .expect("the second execution terminalizes");
    rig.dispatcher.run_deadline_sweep_tick_for_test(now).await;
    let (state, reason) = last_transition(&rig, resumable);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("latched its outcome (cancelled)"),
        "{reason}"
    );
    rig.db
        .release_environment(seeded_environment, i64::MAX / 4)
        .expect("no live attempt binds the environment once both claims are settled");
    let live: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE dispatched_at_ms IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(live, 0, "settling a claim dispatches nothing");
    drop(rig.dir);
}

/// A capsule claim of an execution with NO LIFECYCLE ROW is abandoned too, and the tick
/// settles it PROVEN NOT PERFORMED under a reason that says so: the resume scan
/// enumerates `execution_lifecycle` alone, so nothing will ever re-submit the stage and
/// adopt the claim. The row is deleted through a second writable handle (foreign keys off
/// on that handle only).
///
/// **Would red if:** the abandonment predicate left a claim with no lifecycle row alone
/// (it would stay `pending`, pinning its environment forever), or named an outcome the
/// execution never latched.
#[tokio::test]
async fn a_claim_whose_execution_has_no_lifecycle_row_is_settled_not_performed() {
    let rig = rig();
    let program = shipped_program();
    let orphan = Ulid::new();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(orphan, &program)
        .unwrap();
    let (claimed, _) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
        &rig.db,
        &rig.cas,
        orphan,
        program.program_hash,
        SHIPPED_STAGE,
    );
    let writer = rusqlite::Connection::open(&rig.op_path).unwrap();
    writer.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    let deleted = writer
        .execute(
            "DELETE FROM execution_lifecycle WHERE execution_id = ?1",
            [orphan.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(
        deleted, 1,
        "the premise: the execution has no lifecycle row"
    );
    assert_eq!(
        rig.dispatcher.settle_abandoned_capsule_claims().unwrap(),
        vec![claimed]
    );
    let (state, reason) = last_transition(&rig, claimed);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("has no lifecycle row")
            && !reason.contains("latched")
            && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    drop(rig.dir);
}

/// An authorization whose DISPATCH fails after its claim committed — a storage fault on
/// the command insert, injected through a second writable handle — leaves the claim
/// settled PROVEN NOT PERFORMED by the submit path, with no command, no placement, and no
/// frame on the worker's side.
///
/// A re-submission then mints a FRESH attempt and delivers it.
///
/// **Would red if:** the submit path returned the authorization's error with the claim
/// left `pending` (it would then pin its environment until its execution latched), or the
/// occurrence recovery adopted a SETTLED claim (the re-submission would try to dispatch a
/// terminal attempt and be refused).
#[tokio::test]
async fn a_claim_whose_dispatch_fails_is_settled_not_performed_by_the_submit_path() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let writer = rusqlite::Connection::open(&rig.op_path).unwrap();
    writer
        .execute_batch(
            "CREATE TRIGGER injected_dispatch_fault BEFORE INSERT ON attempt_commands \
             BEGIN SELECT RAISE(ABORT, 'injected storage fault on the dispatch command'); END;",
        )
        .unwrap();
    let runner = runner(&rig);
    let first = directive(&rig).await;
    let error = runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            first,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect_err("the dispatch fails");
    assert!(
        error.to_string().contains("injected storage fault"),
        "{error}"
    );
    writer
        .execute_batch("DROP TRIGGER injected_dispatch_fault;")
        .unwrap();

    let (attempt, dispatched_at): (Vec<u8>, Option<i64>) = raw(&rig.op_path)
        .query_row(
            "SELECT attempt_id, dispatched_at_ms FROM attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("exactly the one claimed attempt");
    assert_eq!(dispatched_at, None);
    let attempt = Ulid::from_bytes(attempt.try_into().unwrap());
    let (state, reason) = last_transition(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("authorization failed after its claim")
            && reason.contains("injected storage fault")
            && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    let commands: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM attempt_commands", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(commands, 0);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(300),
            rig.worker_side.recv_frame()
        )
        .await
        .is_err(),
        "no frame reached the worker"
    );

    // THE NEXT SUBMIT of the same occurrence does not adopt the settled claim — the
    // occurrence recovery reads only a LIVE undispatched attempt — so it mints a fresh
    // one and delivers it.
    let second = directive(&rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            second,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("a re-submission authorizes a new attempt and delivers it");
    let delivered = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => capsule.attempt_id,
    };
    assert_ne!(delivered, attempt, "the settled claim is never delivered");
    let attempts: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        attempts, 2,
        "the settled claim and the fresh, delivered one"
    );
    assert_eq!(last_transition(&rig, attempt).0, "failed");
    drop(rig.dir);
}

/// The UNSENT-CLAIM leg's premise, read under the writer lock
/// (`record_main_side_transition_if_undispatched`), refuses a row that carries EITHER half
/// of a dispatch — not only a row carrying both. The dispatching transaction writes both
/// halves together, so a row where they disagree is not one the leg may call unsent, and
/// recording it PROVEN NOT PERFORMED would be a verdict against an attempt a worker may
/// hold. Each half is made to disagree through a second writable handle: the
/// `dispatched_at_ms` nulled on one delivered attempt, the command row deleted on another.
///
/// **Would red if:** the guard ignored `dispatched_at_ms` (the attempt whose command row was
/// deleted would be recorded `failed`), ignored the command row (the attempt whose
/// `dispatched_at_ms` was nulled would), or ignored both (a fully dispatched attempt would).
#[tokio::test]
async fn the_undispatched_premise_refuses_a_row_carrying_either_half_of_a_dispatch() {
    let transition = kata_core::operational::MainSideTransition {
        reason: Some("the unsent-claim premise must refuse this (rig)"),
        ..kata_core::operational::MainSideTransition::bare("failed")
    };
    // BOTH halves: a delivered attempt, untouched.
    let rig_a = rig();
    let frame_a = dispatched_capsule_attempt(&rig_a).await;
    let both = rig_a
        .db
        .record_main_side_transition_if_undispatched(frame_a.attempt_id, &transition)
        .expect("the guard reads");
    assert_eq!(
        both, None,
        "a fully dispatched attempt is not an unsent claim"
    );
    // ONLY THE COMMAND: `dispatched_at_ms` nulled through a second handle.
    let nulled = rusqlite::Connection::open(&rig_a.op_path)
        .unwrap()
        .execute(
            "UPDATE attempts SET dispatched_at_ms = NULL WHERE attempt_id = ?1",
            [frame_a.attempt_id.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(nulled, 1, "the premise: the dispatch stamp is gone");
    let command_only = rig_a
        .db
        .record_main_side_transition_if_undispatched(frame_a.attempt_id, &transition)
        .expect("the guard reads");
    assert_eq!(
        command_only, None,
        "a commanded attempt is not an unsent claim"
    );
    assert_eq!(last_transition(&rig_a, frame_a.attempt_id).0, "dispatched");

    // ONLY THE DISPATCH STAMP: the command row deleted (foreign keys off on this handle
    // only).
    let rig_b = rig();
    let frame_b = dispatched_capsule_attempt(&rig_b).await;
    let writer = rusqlite::Connection::open(&rig_b.op_path).unwrap();
    writer.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    let deleted = writer
        .execute(
            "DELETE FROM attempt_commands WHERE attempt_id = ?1",
            [frame_b.attempt_id.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(deleted, 1, "the premise: the dispatch command is gone");
    let stamp_only = rig_b
        .db
        .record_main_side_transition_if_undispatched(frame_b.attempt_id, &transition)
        .expect("the guard reads");
    assert_eq!(
        stamp_only, None,
        "a stamped dispatch is not an unsent claim"
    );
    assert_eq!(last_transition(&rig_b, frame_b.attempt_id).0, "dispatched");
    drop(rig_a.dir);
    drop(rig_b.dir);
}

/// The unsent-claim premise DECLINES an attempt that is already terminal — `Ok(None)`,
/// writing nothing — rather than leaving the refusal to the attempt-scope chain latch,
/// whose error a sweep would log as a failed settlement on every tick. The claim here is
/// settled once by the abandoned-claim sweep, then asked again.
///
/// **Would red if:** the premise dropped its own terminal check (the second call would
/// return the latch's `Err` instead of `Ok(None)`).
#[tokio::test]
async fn the_undispatched_premise_declines_a_terminal_claim_without_reaching_the_latch() {
    let rig = rig();
    let program = shipped_program();
    let execution = Ulid::new();
    let face = rig.dispatcher.execution_lifecycle();
    face.put_current_program(execution, &program).unwrap();
    let (claimed, _) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
        &rig.db,
        &rig.cas,
        execution,
        program.program_hash,
        SHIPPED_STAGE,
    );
    face.mark_terminal(
        execution,
        kata_workflow::execution_program_store::ExecutionLifecycleState::Failed,
    )
    .unwrap();
    assert_eq!(
        rig.dispatcher.settle_abandoned_capsule_claims().unwrap(),
        vec![claimed],
        "the premise: the abandoned claim is settled terminal"
    );
    let again = rig.db.record_main_side_transition_if_undispatched(
        claimed,
        &kata_core::operational::MainSideTransition {
            reason: Some("a second settlement (rig)"),
            ..kata_core::operational::MainSideTransition::bare("failed")
        },
    );
    assert_eq!(
        again.expect("declined by the premise, not refused by the latch"),
        None
    );
    drop(rig.dir);
}

/// An authorization that fails BEFORE its own claim point settles nothing — not even a
/// live claim an EARLIER submission left undispatched at the same occurrence. That claim is
/// the occurrence recovery's to adopt: the next submission dispatches it, rather than
/// minting a second generation for work that was never sent.
///
/// The earlier claim is left the way a crash between the claim and the dispatch leaves it:
/// a fault injected on the command insert AND on the settlement's terminal transition, both
/// through a second writable handle. The failing submission then presents a DIVERGENT
/// capsule at the same occurrence, which the authorization refuses before its claim point.
///
/// **Would red if:** the submit path settled whatever undispatched claim sat at the
/// occurrence after any authorization error (the earlier claim would be recorded `failed`,
/// and the third submission would deliver a fresh attempt instead of adopting it).
#[tokio::test]
async fn an_authorization_failing_before_its_claim_leaves_an_earlier_claim_for_adoption() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let writer = rusqlite::Connection::open(&rig.op_path).unwrap();
    writer
        .execute_batch(
            "CREATE TRIGGER injected_dispatch_fault BEFORE INSERT ON attempt_commands \
             BEGIN SELECT RAISE(ABORT, 'injected storage fault on the dispatch command'); END; \
             CREATE TRIGGER injected_settlement_fault BEFORE INSERT ON transitions \
             WHEN NEW.resulting_state = 'failed' \
             BEGIN SELECT RAISE(ABORT, 'injected storage fault on the settlement'); END;",
        )
        .unwrap();
    let runner = runner(&rig);
    let first = directive(&rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            first,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect_err("the dispatch fails");
    writer
        .execute_batch(
            "DROP TRIGGER injected_dispatch_fault; DROP TRIGGER injected_settlement_fault;",
        )
        .unwrap();
    let earlier: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .expect("exactly the one claimed attempt");
    let earlier = Ulid::from_bytes(earlier.try_into().unwrap());
    let (state, reason) = last_transition(&rig, earlier);
    assert_eq!(
        state, "pending",
        "the premise: a live, undispatched claim: {reason}"
    );

    // A SUBMISSION REFUSED BEFORE ITS CLAIM POINT: a different capsule at the occurrence.
    let second = directive(&rig).await;
    let refusal = runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            second,
            &RenderedCommand::rendered("echo divergent"),
        )
        .await
        .expect_err("a divergent capsule at a bound occurrence is refused");
    assert!(
        refusal.to_string().contains("is already bound to capsule"),
        "{refusal}"
    );
    let (state, reason) = last_transition(&rig, earlier);
    assert_eq!(
        state, "pending",
        "a claim the failing authorization never reached is not its to settle: {reason}"
    );

    // THE NEXT SUBMISSION ADOPTS IT.
    let third = directive(&rig).await;
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            third,
            &RenderedCommand::rendered("echo cutover"),
        )
        .await
        .expect("the occurrence recovery adopts the claim and delivers it");
    let delivered = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => capsule.attempt_id,
    };
    assert_eq!(delivered, earlier, "the earlier claim is the one delivered");
    let attempts: i64 = raw(&rig.op_path)
        .query_row("SELECT count(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 1, "no second generation was minted");
    drop(rig.dir);
}

/// THE MAIN-SIDE settlement's standing-stop arm: a capsule attempt an operator stop stands
/// against, settled by a main-side leg (here the worker-death leg), is recorded
/// `cancelled` and names the stop — not `failed`. (The worker-reported arm has its own
/// cell, `a_capsule_failure_under_a_standing_stop_is_recorded_as_cancelled`.)
///
/// **Would red if:** `settle_capsule_attempt` ignored the standing stops it reads (the
/// attempt would be recorded `failed`).
#[tokio::test]
async fn a_capsule_settled_under_a_standing_stop_is_recorded_cancelled() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    rig.db
        .record_stop_request(
            frame.attempt_id,
            frame.lease_epoch,
            frame.placed_on.as_str(),
            "operator cancelled the execution",
        )
        .expect("the stop is recorded against the dispatched attempt");
    rig.dispatcher
        .handle_worker_death(
            WORKER,
            &kata_workflow::dispatcher::WorkerLoss::ConnectionClosed("the rig closed it".into()),
        )
        .await
        .expect("the death leg runs");
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "cancelled", "{reason}");
    assert!(
        reason.contains("operator stop stood against it")
            && reason.contains("operator cancelled the execution")
            && reason.contains("PROVEN AMBIGUOUS"),
        "{reason}"
    );
    drop(rig.dir);
}

/// THE START-DEADLINE LEG RE-READS ITS PREMISE UNDER THE WRITER LOCK. The sweep picks its
/// candidates from a snapshot and then awaits a network send per settlement, so the
/// candidate it settles may be stale. Driven here through the leg's own settlement door
/// with such candidates:
///
/// * a start that FOLDED after the snapshot — the attempt is `running`, its container
///   live — is NOT settled "did not start";
/// * a candidate whose worker has since STARTED another attempt is NOT settled (queued
///   behind it is backpressure);
/// * at the hand-off, once that sibling finishes, the candidate is measured from the
///   worker's freed slot and not its (long past) dispatch: not settled one window after
///   the free, settled one millisecond later.
///
/// **Would red if:** the settlement re-read only "not terminal" under the lock (the
/// original premise), or anchored the window on the dispatch alone.
#[tokio::test]
async fn the_start_deadline_leg_settles_nothing_its_stale_snapshot_no_longer_supports() {
    let rig = rig();
    let program = shipped_program();
    let seed = |started: Option<i64>| {
        let execution = Ulid::new();
        rig.dispatcher
            .execution_lifecycle()
            .put_current_program(execution, &program)
            .unwrap();
        kata_workflow::test_harness::seed_dispatched_capsule_attempt(
            &rig.db,
            &rig.cas,
            execution,
            program.program_hash,
            SHIPPED_STAGE,
            WORKER,
            started,
        )
    };
    let dispatched_at = |attempt: Ulid| -> i64 {
        raw(&rig.op_path)
            .query_row(
                "SELECT dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
                [attempt.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    };
    let far = i64::MAX / 4;

    // A START FOLDED AFTER THE SNAPSHOT.
    let folded = seed(None);
    rig.db
        .record_main_side_transition(
            folded,
            &kata_core::operational::MainSideTransition {
                started_at_ms: Some(dispatched_at(folded) + 5),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .unwrap();
    assert!(
        !rig.dispatcher
            .settle_overdue_capsule_attempt_for_test(folded, WORKER, far)
            .await
            .unwrap(),
        "a started attempt is never settled as one that did not start"
    );
    assert_eq!(last_transition(&rig, folded).0, "running");
    // That started attempt now holds the worker: a queued candidate is not overdue.
    let queued = seed(None);
    assert!(
        !rig.dispatcher
            .settle_overdue_capsule_attempt_for_test(queued, WORKER, far)
            .await
            .unwrap(),
        "a candidate queued behind a started attempt is backpressure"
    );
    assert_eq!(last_transition(&rig, queued).0, "dispatched");

    // THE HAND-OFF: the started attempt finishes; the queue is measured from the freed slot.
    rig.db
        .record_main_side_transition(
            folded,
            &kata_core::operational::MainSideTransition {
                reason: Some("finished (rig)"),
                // A dispatched attempt's terminal states its charge
                // (`terminal_charge_required`); a shell capsule bills nothing.
                terminal_charge: Some(&kata_types::metering::TerminalCharge::of_usage(
                    kata_types::metering::StageUsage::unbilled(),
                )),
                ..kata_core::operational::MainSideTransition::bare("failed")
            },
        )
        .unwrap();
    let freed: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT finished_at_ms FROM attempts WHERE attempt_id = ?1",
            [folded.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the finished attempt records when the slot freed");
    let window =
        15 * 60 * 1000 + i64::try_from(kata_workflow::dispatcher::CAPSULE_START_GRACE_MS).unwrap();
    assert!(
        !rig.dispatcher
            .settle_overdue_capsule_attempt_for_test(queued, WORKER, freed + window)
            .await
            .unwrap(),
        "one window after the slot freed, and not after it, nothing is overdue"
    );
    assert!(
        rig.dispatcher
            .settle_overdue_capsule_attempt_for_test(queued, WORKER, freed + window + 1)
            .await
            .unwrap(),
        "one millisecond later the queued capsule is overdue and settled"
    );
    let (state, reason) = last_transition(&rig, queued);
    assert_eq!(state, "failed", "{reason}");
    drop(rig.dir);
}

/// The start-deadline premise anchors a queued candidate on the LATEST moment its
/// worker's slot freed, not the earliest: with two finished started siblings — one freed
/// before the candidate's dispatch, one ten minutes after it — one window past the later
/// free settles nothing. (Finish stamps are written through a second writable handle.)
///
/// **Would red if:** the slot-freed read took the earliest finish (the candidate would be
/// measured from its dispatch and settled ten minutes early).
#[tokio::test]
async fn the_start_deadline_premise_anchors_on_the_latest_freed_slot() {
    let rig = rig();
    let program = shipped_program();
    let seed = |started: Option<i64>| {
        let execution = Ulid::new();
        rig.dispatcher
            .execution_lifecycle()
            .put_current_program(execution, &program)
            .unwrap();
        kata_workflow::test_harness::seed_dispatched_capsule_attempt(
            &rig.db,
            &rig.cas,
            execution,
            program.program_hash,
            SHIPPED_STAGE,
            WORKER,
            started,
        )
    };
    let finish = |attempt: Ulid| {
        rig.db
            .record_main_side_transition(
                attempt,
                &kata_core::operational::MainSideTransition {
                    reason: Some("finished (rig)"),
                    // A dispatched attempt's terminal states its charge
                    // (`terminal_charge_required`); a shell capsule bills nothing.
                    terminal_charge: Some(&kata_types::metering::TerminalCharge::of_usage(
                        kata_types::metering::StageUsage::unbilled(),
                    )),
                    ..kata_core::operational::MainSideTransition::bare("failed")
                },
            )
            .unwrap();
    };
    let (early, late) = (seed(Some(1)), seed(Some(2)));
    finish(early);
    finish(late);
    let queued = seed(None);
    let dispatched: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
            [queued.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let late_freed = dispatched + 10 * 60 * 1000;
    let writer = rusqlite::Connection::open(&rig.op_path).unwrap();
    for (attempt, finished) in [(early, dispatched - 1000), (late, late_freed)] {
        writer
            .execute(
                "UPDATE attempts SET finished_at_ms = ?1 WHERE attempt_id = ?2",
                rusqlite::params![finished, attempt.to_bytes().as_slice()],
            )
            .unwrap();
    }
    let window =
        15 * 60 * 1000 + i64::try_from(kata_workflow::dispatcher::CAPSULE_START_GRACE_MS).unwrap();
    assert!(
        !rig.dispatcher
            .settle_overdue_capsule_attempt_for_test(queued, WORKER, late_freed + window)
            .await
            .unwrap(),
        "one window after the LATEST free, nothing is overdue"
    );
    assert_eq!(last_transition(&rig, queued).0, "dispatched");
    assert!(
        rig.dispatcher
            .settle_overdue_capsule_attempt_for_test(queued, WORKER, late_freed + window + 1)
            .await
            .unwrap(),
        "non-vacuity: one millisecond later it is overdue and settled"
    );
    drop(rig.dir);
}

/// A STORAGE FAULT reading a reported result is not a verdict on it: the reactor records
/// NOTHING and the attempt stays live, so a transient EIO cannot permanently fail a stage
/// that succeeded. The fault is real — the result manifest is large enough to be a blob
/// FILE, and the file is made unreadable (mode 000) after the store's row records it, so
/// the row says the manifest is there at the claimed length and the read fails on the
/// disk. A genuine verdict on the result is still recorded; that half is
/// `a_refused_capsule_result_is_recorded_failed_ambiguous`.
///
/// **Would red if:** the adoption wrapped the store's read error as a refusal again (the
/// attempt would be recorded `failed`).
#[tokio::test]
async fn a_storage_fault_reading_a_result_records_nothing_and_leaves_the_attempt_live() {
    use std::os::unix::fs::PermissionsExt;
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    // Thirty entries with 4000-byte paths: a manifest over the 100 KiB inline threshold,
    // so it is stored as a FILE; one tiny member shared by every entry.
    let member = rig.cas.put_durable(b"m\n").unwrap();
    let entries = (0..30)
        .map(|index| kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new(format!(
                "d/{index:02}{}",
                "a".repeat(4000)
            ))
            .unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        })
        .collect();
    let manifest = kata_types::tree_artifact::TreeManifest::new(entries).unwrap();
    let durable = rig
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    assert!(
        durable.size() > 100 * 1024,
        "the premise: a blob FILE, not an inline row"
    );
    let blobs = rig
        .dir
        .as_ref()
        .expect("a fresh rig owns its directory")
        .path()
        .join("cas");
    // The frame is BUILT before the fault lands: under v6 the completion names two
    // capture blob refs, and `publish_capture` would hit the same broken store the
    // adoption is being fault-tested against — the frame must already exist.
    let completion = completed_capsule(
        &rig,
        &frame,
        kata_types::execution_contract::ArtifactRef::new(
            durable.object_id(),
            durable.size(),
            kata_types::execution_contract::ArtifactPrivacy::Private,
        ),
    );
    let mut locked = 0;
    for entry in walk(&blobs) {
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o000)).unwrap();
        locked += 1;
    }
    assert!(locked >= 1, "the manifest's blob file was found and locked");
    let error = reactor(&rig)
        .handle_message_for_test(completion)
        .expect_err("the fault still leaves the arm, so the loop logs it");
    assert!(
        matches!(error, kata_types::KataError::Storage(_)),
        "a storage fault, not a refusal: {error:?}"
    );
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "nothing is recorded for a fault in the store"
    );
    for entry in walk(&blobs) {
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    drop(rig.dir);
}

/// A one-member result tree over `member_bytes`, published into the rig's store; returns
/// the member's receipt and the result reference a worker would report.
fn one_member_result(
    rig: &Rig,
    member_bytes: &[u8],
) -> (
    kata_core::store::cas::DurableObject,
    kata_types::execution_contract::ArtifactRef,
) {
    let member = rig.cas.put_durable(member_bytes).unwrap();
    let manifest =
        kata_types::tree_artifact::TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new("result.txt").unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        }])
        .unwrap();
    let durable = rig
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let result = kata_types::execution_contract::ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    );
    (member, result)
}

/// A WRITABLE second handle onto the rig's `cas.db` — the instrument that induces a store
/// fault. Never used to observe.
fn cas_db_writer(rig: &Rig) -> rusqlite::Connection {
    rusqlite::Connection::open(
        rig.dir
            .as_ref()
            .expect("a fresh rig owns its directory")
            .path()
            .join("cas.db"),
    )
    .unwrap()
}

/// The CAPSULE's OWN bytes failing verification during adoption are a STORAGE fault, not a
/// verdict on the reported result: `adopt_and_accept_capsule_completion`'s refused set
/// names "a read of the capsule's own bytes" as propagated. The fault is real: the
/// capsule's inline row is zeroed on a second handle, so the store holds the row at its
/// length and the bytes no longer hash to their address. The reported result is
/// well-formed, so a refusal could only have come from the fault.
///
/// **Would red if:** the capsule-bytes read's error were wrapped as a result refusal (the
/// attempt would be recorded `failed`).
#[tokio::test]
async fn a_corrupt_capsule_object_during_adoption_is_a_storage_fault_not_a_refusal() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let (_member, result) = one_member_result(&rig, b"k05\n");
    let capsule_object: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT capsule_object_id FROM capsules", [], |row| {
            row.get(0)
        })
        .expect("one capsule");
    let changed = cas_db_writer(&rig)
        .execute(
            "UPDATE cas_objects SET blob = zeroblob(length(blob)) WHERE object_id = ?1 \
               AND storage = 'inline'",
            [capsule_object.as_slice()],
        )
        .unwrap();
    assert_eq!(
        changed, 1,
        "the premise: the capsule object is an INLINE row"
    );
    let error = reactor(&rig)
        .handle_message_for_test(completed_capsule(&rig, &frame, result))
        .expect_err("the adoption cannot read the capsule");
    assert!(
        matches!(error, kata_types::KataError::Storage(_)),
        "a storage fault, not a refusal: {error:?}"
    );
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "nothing is recorded for a fault in the store"
    );
    drop(rig.dir);
}

/// A MEMBER ROW the store cannot read back during adoption is a STORAGE fault, not a
/// verdict on the reported result — the third kind the refused set says propagates ("a
/// member row that cannot be read"). The fault is real and confined to that one row: the
/// member's `cas_objects.size` is made negative on a second handle, which the store's own
/// reader refuses as corruption. The manifest row is untouched, so every step before the
/// member check reads cleanly.
///
/// **Would red if:** the member check's store error were wrapped as a result refusal
/// alongside its absent/mis-measured verdicts (the attempt would be recorded `failed`).
#[tokio::test]
async fn an_unreadable_member_row_during_adoption_is_a_storage_fault_not_a_refusal() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let (member, result) = one_member_result(&rig, b"m06\n");
    let changed = cas_db_writer(&rig)
        .execute(
            "UPDATE cas_objects SET size = -1 WHERE object_id = ?1",
            [member.object_id().0.as_slice()],
        )
        .unwrap();
    assert_eq!(changed, 1, "the premise: the member's row exists");
    let error = reactor(&rig)
        .handle_message_for_test(completed_capsule(&rig, &frame, result))
        .expect_err("the adoption cannot read the member's row");
    assert!(
        matches!(&error, kata_types::KataError::Storage(message) if message.contains("negative")),
        "the store's own fault, propagated: {error:?}"
    );
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "nothing is recorded for a fault in the store"
    );
    drop(rig.dir);
}

/// Every regular file beneath `root`.
fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files
}

// -- every worker leg and blob reader names the MAIN arm ------------------------------

/// A main attempt's raw row and chain, for "nothing touched it".
fn main_attempt_footprint(rig: &Rig, attempt: Ulid) -> (String, Option<i64>, i64, i64) {
    raw(&rig.op_path)
        .query_row(
            "SELECT p.state, a.wait_deadline_ms, a.lease_epoch,
                    (SELECT COUNT(*) FROM transitions t WHERE t.attempt_id = a.attempt_id)
               FROM attempts a JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("the main attempt's row")
}

fn main_spec(rig: &Rig, path: Vec<u32>) -> kata_core::operational::MainAttemptSpec {
    kata_core::operational::MainAttemptSpec {
        stage_id: SHIPPED_STAGE.to_string(),
        occurrence: kata_core::operational::OccurrenceBinding::new(
            kata_types::execution_contract::OccurrenceRef::new(
                kata_types::workflow::ExecutionId(rig.execution_id),
                shipped_program().program_hash,
                kata_types::execution_contract::OperationContractId(ContentHash::new([0x7E; 32])),
                kata_types::execution_contract::OperationPath(path),
            ),
            None,
            None,
        ),
    }
}

/// Schema 24 — a MAIN-RESOLVED attempt in an execution beside a live CAPSULE attempt is
/// excluded BY NAME from every worker leg and every reader of the stored blob, and none of
/// them aborts on it:
///
/// * the live-work registry (which feeds the deadline, retry, death, stall and boot-orphan
///   legs) omits it, and the runner's stage states CARRY it by its `stage_id`, parked waits
///   non-terminal and the resolved join terminal;
/// * the assignment POPULATION omits it and does not refuse the execution;
/// * the delivery MAPPING (IR-4) folds its resolution as `Completed { worker_id: None }`
///   and its park as no wire event, and the page does not abort — so the runner fold reads
///   the execution past it;
/// * the restart, abandoned-claim, deadline-tick (wall time), worker-death and boot-orphan
///   legs settle the CAPSULE attempt and leave the main attempts' rows untouched, which is
///   also the proof that each pass reached its capsule candidate rather than aborting.
///
/// Every "untouched" is read through a second raw handle.
#[tokio::test]
async fn every_worker_leg_and_blob_reader_names_a_main_attempt_and_none_aborts() {
    use kata_core::operational::{MainOperation, MainResolution, MainWait};
    use kata_types::wait::WaitDeadline;
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;

    // Three main attempts in the SAME execution: a timer no tick of this cell reaches (its
    // deadline is the largest instant; the tick below runs past the capsule's wall time,
    // which would make a merely-late deadline due), an unbounded input
    // wait, and a join already resolved and accepted. (A DUE timer is resolved by the
    // tick's main-side due-wait leg, by design — the durable-timer cells pin that; the
    // property here is that no WORKER leg reaches a main attempt.)
    let timer = Ulid::new();
    rig.db
        .claim_main_attempt(
            timer,
            &main_spec(&rig, vec![90]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: i64::MAX }),
        )
        .expect("claim the timer");
    let input = Ulid::new();
    rig.db
        .claim_main_attempt(input, &main_spec(&rig, vec![91]), MainWait::Input(None))
        .expect("claim the input wait");
    let join = Ulid::new();
    let joined = serde_json::json!({"joined": []});
    rig.db
        .claim_and_resolve_main_attempt(
            join,
            &main_spec(&rig, vec![92]),
            MainOperation::Join,
            &MainResolution::Complete { output: &joined },
        )
        .expect("claim and resolve the join");
    let mains = [timer, input, join];
    let before: Vec<_> = mains
        .iter()
        .map(|attempt| main_attempt_footprint(&rig, *attempt))
        .collect();

    // The registry every worker sweep discovers through, and the runner's predicates.
    let live: Vec<Ulid> = rig
        .dispatcher
        .live_work_registry()
        .expect("the registry reads past a main attempt")
        .into_iter()
        .map(|work| work.assignment_id)
        .collect();
    assert!(live.contains(&frame.attempt_id), "non-vacuity: {live:?}");
    assert!(mains.iter().all(|main| !live.contains(main)), "{live:?}");
    // The runner's stage states CARRY every main attempt — named by its `stage_id`, in its
    // folded state — beside the capsule attempt, so a consumer deciding from
    // non-terminality sees a parked wait.
    let stages = rig
        .dispatcher
        .execution_stage_states(rig.execution_id)
        .expect("the runner predicates read a main attempt");
    assert!(
        stages
            .iter()
            .any(|state| state.assignment_id == frame.attempt_id),
        "non-vacuity: {stages:?}"
    );
    let main_states: Vec<(Ulid, String, Option<String>, bool)> = mains
        .iter()
        .map(|main| {
            let state = stages
                .iter()
                .find(|state| state.assignment_id == *main)
                .unwrap_or_else(|| panic!("main attempt {main} is a stage state: {stages:?}"));
            (
                *main,
                state.stage_name.clone(),
                state.state.clone(),
                state.is_terminal(),
            )
        })
        .collect();
    assert_eq!(
        main_states,
        vec![
            (
                timer,
                SHIPPED_STAGE.to_string(),
                Some("awaiting_timer".to_string()),
                false
            ),
            (
                input,
                SHIPPED_STAGE.to_string(),
                Some("awaiting_input".to_string()),
                false
            ),
            (
                join,
                SHIPPED_STAGE.to_string(),
                Some("completed".to_string()),
                true
            ),
        ]
    );

    // The assignment population and the delivery mapping.
    let mapper = kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(Arc::clone(&rig.db));
    let population = mapper
        .execution_assignment_states(rig.execution_id)
        .expect("the population reads past a main attempt");
    assert!(
        population
            .iter()
            .all(|state| !mains.contains(&state.assignment_id)),
        "a main attempt has no work unit to populate"
    );
    let page = mapper
        .map_page(rig.execution_id, 1, 1_000)
        .expect("IR-4: the page maps past every main frame");
    let join_events: Vec<_> = page
        .mapped
        .iter()
        .filter_map(|mapped| match mapped {
            kata_workflow::attempt_delivery::MappedFrame::Delivery(delivery) => Some(
                kata_workflow::attempt_delivery::foldable_frame(delivery)
                    .expect("a mapped frame folds")
                    .event,
            ),
            kata_workflow::attempt_delivery::MappedFrame::Checkpoint { .. } => None,
        })
        .filter(|event| event.assignment_id == join)
        .collect();
    assert_eq!(
        join_events.len(),
        2,
        "the join's claim and resolution: {join_events:?}"
    );
    assert_eq!(
        join_events[0].new_status,
        kata_types::ledger::AssignmentStatus::Pending
    );
    assert_eq!(
        join_events[1].new_status,
        kata_types::ledger::AssignmentStatus::Completed { worker_id: None },
        "a main resolution completes with NO worker — the wire's own shape for it"
    );
    assert_eq!(join_events[1].output.as_ref(), Some(&joined));

    // The deadline TICK: it discovers through the registry first and returns early if
    // that fails, so settling the started capsule attempt past its wall clock is the
    // proof the tick ran to its capsule leg.
    reactor(&rig)
        .handle_message_for_test(start_checkpoint(&frame))
        .expect("the start checkpoint folds");
    let started_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT started_at_ms FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let wall = i64::try_from(kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS).unwrap();
    let grace = i64::try_from(kata_workflow::dispatcher::CAPSULE_WALL_TIME_GRACE_MS).unwrap();
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(u64::try_from(started_at + wall + grace + 1).unwrap())
        .await;
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "failed",
        "non-vacuity: the tick reached its capsule wall-time leg"
    );

    // The capsule settlement legs that read `live_attempts` directly — after the tick,
    // because the restart leg would otherwise settle the capsule attempt the tick needs.
    let restarted = rig
        .dispatcher
        .settle_capsule_attempts_after_restart()
        .expect("the restart leg reads past a main attempt");
    assert!(mains.iter().all(|main| !restarted.contains(main)));
    let abandoned = rig
        .dispatcher
        .settle_abandoned_capsule_claims()
        .expect("the abandoned-claim leg reads past a main attempt");
    assert!(mains.iter().all(|main| !abandoned.contains(main)));

    // The death and boot-orphan legs, over a registry that still holds a main attempt.
    rig.dispatcher
        .handle_worker_death(
            WORKER,
            &kata_workflow::dispatcher::WorkerLoss::ConnectionClosed("the rig closed it".into()),
        )
        .await
        .expect("the worker-death leg reads past a main attempt");
    rig.dispatcher
        .orphan_in_flight_runs("main-arm cell", &std::collections::BTreeSet::new())
        .expect("the boot-orphan leg reads past a main attempt");

    let after: Vec<_> = mains
        .iter()
        .map(|attempt| main_attempt_footprint(&rig, *attempt))
        .collect();
    assert_eq!(after, before, "no worker leg touched a main attempt");
    assert_eq!(after[0].0, "awaiting_timer");
    assert_eq!(after[1].0, "awaiting_input");
    assert_eq!(after[2].0, "completed");
    drop(rig.dir);
}

// -- the `parallel()` join, resolved MAIN-SIDE ----------------------------------------

/// The SHIPPED outputs-only join smoke: `left` and `right` fan out, `parallel()` mints the
/// join, and `collector` renders both branches' parsed values.
const JOIN_PACK: &str = include_str!("../../../workflows/smoke/join-outputs-smoke.star");
const JOIN_STAGE: &str = "__parallel_join_0";
const JOIN_INPUTS: [&str; 2] = ["left", "right"];

/// The join smoke compiled under `oci` — the profile's own CHECK door.
fn join_program() -> kata_program::execution_program::ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(JOIN_PACK, "join-outputs-smoke.star", &[])
        .expect("the join smoke compiles under oci")
}

/// The runner over the join smoke, its execution ADMITTED by `put_current_program`.
fn join_runner(rig: &Rig) -> WorkflowRunner {
    let program = join_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(rig.execution_id, &program)
        .expect("the program is retained");
    seed_scratch_head(rig);
    WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
        .expect("the runner builds")
        .with_cache_store(Arc::clone(&rig.store))
}

/// The directive `stage`'s own sandbox resolves to, through the production resolver.
async fn join_directive(rig: &Rig, stage: &str) -> Option<kata_types::sandbox::SandboxDirective> {
    let program = join_program();
    let stage = program
        .stages
        .get(&StageId(SmolStr::new(stage)))
        .expect("the pack's stage");
    rig.dispatcher
        .resolve_sandbox(
            stage.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            rig.execution_id,
            stage.should_confine_to_declared_inputs(),
            stage.is_content_cacheable(),
        )
        .await
        .expect("the stage's profile resolves")
}

/// The canonical EMPTY tree as a result reference — what a shell stage that writes no
/// `/out` file reports, admitted `Public` by the adoption door.
fn empty_tree_result() -> kata_types::execution_contract::ArtifactRef {
    let manifest = kata_types::tree_artifact::TreeManifest::new(Vec::new())
        .unwrap()
        .manifest_bytes()
        .unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&manifest),
        u64::try_from(manifest.len()).unwrap(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
}

/// THE STUB WORKER's one step: take the next delivered capsule frame, read the capsule's
/// argv out of the node's CAS (the bytes a container would `execve`), RUN it with the
/// host's own `sh`, and report the completion — stdout and exit code — through the reactor.
/// Answers the stage the attempt belongs to, read raw.
async fn run_next_capsule(rig: &Rig, reactor: &kata_workflow::reactor::ResultReactor) -> String {
    let frame = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a capsule frame reaches the worker")
    .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    };
    let bytes = rig
        .cas
        .get(&frame.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    let argv: Vec<String> = match capsule.process() {
        kata_types::execution_contract::CapsuleProcess::Command { argv } => {
            argv.iter().map(ToString::to_string).collect()
        }
        kata_types::execution_contract::CapsuleProcess::Agent(..) => {
            panic!("the fixture stage is a Command capsule")
        }
    };
    let ran = std::process::Command::new("sh")
        .args(&argv[1..])
        .output()
        .expect("the host shell runs the capsule's command");
    // The stub worker IS the provider side: publish both streams as the blobs
    // v6 carries, and flag `capture_exceeded` the way a real provider would —
    // past the COMBINED bound the assignment's `CaptureSpec::limit_bytes` sets,
    // which is the capsule's own `output_bytes`.
    let limit = capsule.budgets().output_bytes;
    let capture_exceeded = ran.stdout.len() as u64 + ran.stderr.len() as u64 > limit;
    reactor
        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: fence_of(&frame),
            result: empty_tree_result(),
            work_delta: stub_work_delta(rig, &frame),
            exit_code: ran.status.code(),
            stdout: publish_capture(rig, &ran.stdout),
            stderr: publish_capture(rig, &ran.stderr),
            capture_exceeded,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "join cell",
            ),
            egress_refusals: vec![],
        })
        .expect("the completion is adopted and accepted");
    raw(&rig.op_path)
        .query_row(
            "SELECT stage_id FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt's stage")
}

/// Submit `stage` through the capsule door with its pack command, and run it to acceptance.
async fn accept_input(
    rig: &Rig,
    runner: &WorkflowRunner,
    reactor: &kata_workflow::reactor::ResultReactor,
    stage: &str,
) {
    let command = format!("printf '{{\"value\":\"{stage}-value\"}}\\n'");
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(stage),
            join_directive(rig, stage).await,
            &RenderedCommand::rendered(command),
        )
        .await
        .expect("the input is authorized and delivered");
    assert_eq!(run_next_capsule(rig, reactor).await, stage);
}

/// The JOIN's durable footprint, read raw: `(join occurrences, join attempts, their
/// executor, capsules at the join's occurrence, commands for its attempts)`.
fn join_footprint(rig: &Rig) -> (i64, i64, Vec<String>, i64, i64) {
    let conn = raw(&rig.op_path);
    let executors: Vec<String> = {
        let mut statement = conn
            .prepare("SELECT executor FROM attempts WHERE stage_id = ?1")
            .unwrap();
        statement
            .query_map([JOIN_STAGE], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    conn.query_row(
        "SELECT
            (SELECT count(DISTINCT occurrence_id) FROM attempts WHERE stage_id = ?1),
            (SELECT count(*) FROM attempts WHERE stage_id = ?1),
            (SELECT count(*) FROM capsules WHERE occurrence_id IN
                (SELECT occurrence_id FROM attempts WHERE stage_id = ?1)),
            (SELECT count(*) FROM attempt_commands WHERE attempt_id IN
                (SELECT attempt_id FROM attempts WHERE stage_id = ?1))",
        [JOIN_STAGE],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                executors.clone(),
                row.get(2)?,
                row.get(3)?,
            ))
        },
    )
    .unwrap()
}

/// The `(accepted_at_ms, accepting seq)` of `stage`'s accepted occurrence, read raw — the
/// seq is the accepting attempt's `completed` transition.
fn acceptance_of(rig: &Rig, stage: &str) -> (i64, i64) {
    raw(&rig.op_path)
        .query_row(
            "SELECT o.accepted_at_ms, t.seq FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE a.stage_id = ?1",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("{stage} has one accepted occurrence: {error}"))
}

/// The accepted join's recorded output, raw off its accepting transition.
fn join_output(rig: &Rig) -> serde_json::Value {
    let payload: String = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.output') FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE a.stage_id = ?1",
            [JOIN_STAGE],
            |row| row.get(0),
        )
        .expect("the join's accepting transition carries its output");
    serde_json::from_str(&payload).unwrap()
}

/// The input occurrence ids, hex, in the join's input order, read raw.
fn input_occurrences_hex(rig: &Rig) -> Vec<String> {
    JOIN_INPUTS
        .iter()
        .map(|stage| {
            raw(&rig.op_path)
                .query_row(
                    "SELECT lower(hex(occurrence_id)) FROM attempts WHERE stage_id = ?1",
                    [stage],
                    |row| row.get(0),
                )
                .expect("the input's occurrence")
        })
        .collect()
}

/// DRIVE the whole join smoke through `WorkflowRunner::run` — the production submit path,
/// divert CONDITION included — with the stub worker answering every capsule it is handed.
/// Answers the run's outputs and every stage a capsule was delivered for.
async fn drive_join_smoke(
    rig: &Rig,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<String>,
) {
    declare_promoted_environment(rig);
    let runner = join_runner(rig);
    let reactor = reactor(rig);
    let mut capsule_stages = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                stage = run_next_capsule(rig, &reactor) => capsule_stages.push(stage),
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    (outcome, capsule_stages)
}

/// The join is resolved MAIN-SIDE: through the whole drive, its occurrence is accepted by
/// ONE `executor = 'main'` attempt, and no capsule and no dispatch command
/// exists for it — read through a second raw handle — and no frame was delivered for it.
///
/// **Watched red:** with the divert's `Join` arm routed to the capsule path, the join is
/// assembled and delivered as a capsule (a worker attempt, one capsule, one command).
#[tokio::test]
async fn a_join_resolves_main_side_with_no_capsule_or_dispatch() {
    let rig = rig();
    let (outcome, capsule_stages) = drive_join_smoke(&rig).await;
    outcome.expect("the join smoke completes under oci");
    assert!(
        !capsule_stages.iter().any(|stage| stage == JOIN_STAGE),
        "no frame was delivered for the join: {capsule_stages:?}"
    );
    assert_eq!(
        join_footprint(&rig),
        (1, 1, vec!["main".to_string()], 0, 0),
        "one occurrence, one MAIN attempt, no capsule, no command"
    );
    let accepted_by_main: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM occurrences o JOIN attempts a
                ON a.attempt_id = o.accepted_attempt_id
             WHERE a.stage_id = ?1 AND a.executor = 'main'",
            [JOIN_STAGE],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted_by_main, 1, "accepted by the main attempt");
    drop(rig.dir);
}

/// A MAIN-RESOLVED COMPLETION REACHES THE FOLD: the whole drive loop completes a program
/// with a join under `oci` — the join's `Completed { worker_id: None }` is folded, its
/// successor is released, and `collector` renders BOTH branches' parsed values. The
/// rendered value is read off the run's outputs AND off the collector's capsule, whose argv
/// the stub worker ran on the host shell.
///
/// **Watched red:** with `envelope_for` mapping a main resolution's `completed` as a
/// worker completion again (`Some(worker()?)`), the page aborts at the join's frame and the
/// run never completes.
#[tokio::test]
async fn a_main_resolved_completion_reaches_the_fold() {
    let rig = rig();
    let (outcome, capsule_stages) = drive_join_smoke(&rig).await;
    let outputs = outcome.expect("the drive loop completes the join smoke under oci");
    assert_eq!(
        capsule_stages
            .iter()
            .filter(|stage| *stage == "collector")
            .count(),
        1,
        "the collector ran once, after the join: {capsule_stages:?}"
    );
    assert_eq!(
        outputs[JOIN_STAGE],
        serde_json::json!({ "joined": input_occurrences_hex(&rig) }),
        "the fold carries the join's accepted output"
    );
    assert_eq!(
        outputs["collector"]["parsed"]["combined"], "left-value+right-value",
        "the collector rendered both inputs' outputs: {outputs:?}"
    );
    drop(rig.dir);
}

/// The join is ACCEPTED AFTER EVERY INPUT, read raw: its `accepted_at_ms` is at or after
/// each input occurrence's, and its accepting transition's seq after each input's — and a
/// join presented while one input is still running is refused and resolves once both are.
///
/// **Watched red:** with `resolve_join`'s precondition dropped, the early presentation is
/// accepted before `right`'s acceptance.
#[tokio::test]
async fn a_join_is_accepted_after_every_input() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = join_runner(&rig);
    let reactor = reactor(&rig);
    accept_input(&rig, &runner, &reactor, "left").await;
    // `right` is authorized and delivered, and not yet completed.
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new("right"),
            join_directive(&rig, "right").await,
            &RenderedCommand::rendered("printf '{\"value\":\"right-value\"}\\n'"),
        )
        .await
        .expect("right is delivered");
    let early = runner.divert_under_capsule_profile_for_test(&SmolStr::new(JOIN_STAGE));
    assert!(early.is_err(), "the join waits for right: {early:?}");
    assert_eq!(run_next_capsule(&rig, &reactor).await, "right");
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new(JOIN_STAGE))
            .expect("with both inputs accepted the join resolves"),
        "resolved main-side"
    );
    let join = acceptance_of(&rig, JOIN_STAGE);
    for input in JOIN_INPUTS {
        let accepted = acceptance_of(&rig, input);
        assert!(
            join.0 >= accepted.0 && join.1 > accepted.1,
            "the join {join:?} is accepted after {input} {accepted:?}"
        );
    }
    assert_eq!(
        join_output(&rig),
        serde_json::json!({ "joined": input_occurrences_hex(&rig) })
    );
    drop(rig.dir);
}

/// A join over an UNACCEPTED input is refused by name (`join_input_unaccepted`) and WRITES
/// NOTHING: the plane's row counts and transition head are unchanged, read raw.
///
/// **Watched red:** with `resolve_join`'s precondition dropped, the join is claimed and
/// accepted over an input that has no outcome.
#[tokio::test]
async fn a_join_over_an_unaccepted_input_is_refused_and_writes_nothing() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = join_runner(&rig);
    let reactor = reactor(&rig);
    accept_input(&rig, &runner, &reactor, "left").await;
    let plane = |rig: &Rig| -> (i64, i64, i64) {
        raw(&rig.op_path)
            .query_row(
                "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM attempts),
                        (SELECT coalesce(max(seq), 0) FROM transitions)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    };
    let before = plane(&rig);
    let refusal = runner
        .divert_under_capsule_profile_for_test(&SmolStr::new(JOIN_STAGE))
        .expect_err("right was never accepted")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::JOIN_INPUT_UNACCEPTED),
        "refused by name: {refusal}"
    );
    assert_eq!(plane(&rig), before, "nothing of the join was written");
    drop(rig.dir);
}

/// A RESUBMITTED join CONVERGES: presenting the accepted join again answers `Ok`, writes
/// no second attempt, occurrence or transition, and leaves the accepted output unchanged.
///
/// **Watched red:** with the substrate's convergence (`converge_in_tx`) answering "nothing
/// here", the second presentation claims a second attempt or is refused.
#[tokio::test]
async fn a_resubmitted_join_converges() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = join_runner(&rig);
    let reactor = reactor(&rig);
    for input in JOIN_INPUTS {
        accept_input(&rig, &runner, &reactor, input).await;
    }
    let join = SmolStr::new(JOIN_STAGE);
    assert!(runner.divert_under_capsule_profile_for_test(&join).unwrap());
    let head = |rig: &Rig| -> i64 {
        raw(&rig.op_path)
            .query_row("SELECT max(seq) FROM transitions", [], |row| row.get(0))
            .unwrap()
    };
    let (before, output) = (head(&rig), join_output(&rig));
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&join)
            .expect("a re-presented join converges"),
        "and is still resolved main-side"
    );
    assert_eq!(head(&rig), before, "no transition was written");
    assert_eq!(join_footprint(&rig), (1, 1, vec!["main".to_string()], 0, 0));
    assert_eq!(join_output(&rig), output);
    drop(rig.dir);
}

/// The child of the join's crash cell, told where and what by these.
const JOIN_CRASH_CHILD: &str = "KATA_CUTOVER_JOIN_CRASH_CHILD";
const JOIN_CRASH_DIR: &str = "KATA_CUTOVER_JOIN_CRASH_DIR";
const JOIN_CRASH_EXECUTION: &str = "KATA_CUTOVER_JOIN_CRASH_EXECUTION";
const JOIN_CRASH_CELL: &str = "a_join_crashed_at_its_commit_resolves_exactly_once_after_restart";
/// Printed by the child immediately before it presents the join, so the parent can prove
/// the abort was the JOIN's transaction and not an earlier one.
const JOIN_CRASH_REACHED: &str = "join-crash-child: presenting the join";

/// The planes a crash CHILD opens: the operational plane and a dispatcher over it, and
/// NOTHING that writes — no worker enrolment — so the first typed transaction the child
/// commits is the join's.
fn crash_child_runner(path: &Path, execution_id: Ulid) -> WorkflowRunner {
    let store = Arc::new(
        kata_core::store::SqliteWorkflowStore::open(path.join("workflow.db"))
            .expect("the stage-cache store opens"),
    );
    let db = Arc::new(
        OperationalDb::open_with_cas(path.join("operational.db"), store.shared_cas())
            .expect("the operational plane opens"),
    );
    let dispatcher = Arc::new(
        Dispatcher::new(
            Arc::new(WorkerPoolSupervisor::new()),
            Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(30),
            )),
            kata_core::InFlightLedger::in_memory(),
        )
        .with_node_environment(boot_binding())
        .with_execution_lifecycle(
            kata_workflow::execution_lifecycle::ExecutionLifecycleFace::new(db),
        ),
    );
    WorkflowRunner::new_from_program(join_program(), dispatcher, execution_id)
        .expect("the runner builds")
        .with_cache_store(store)
}

/// K3 / K4 ON THE JOIN'S TRANSACTION, then a RESTART: a main that dies before the join's
/// commit (K3, `before_txn_commit`) leaves nothing of it, and one that dies after (K4,
/// `after_txn_commit`) leaves it accepted. Either way the SUCCESSOR — a fresh process's
/// planes over the same data directory, presenting the join through the same divert —
/// leaves exactly ONE join occurrence and ONE join attempt, accepted by main. Driven by a
/// real abort in a child process; the child proves it reached the join before it died;
/// every count is read raw.
#[tokio::test]
async fn a_join_crashed_at_its_commit_resolves_exactly_once_after_restart() {
    if let Some(dir) = std::env::var_os(JOIN_CRASH_DIR)
        && std::env::var_os(JOIN_CRASH_CHILD).is_some()
    {
        let execution = Ulid::from_string(&std::env::var(JOIN_CRASH_EXECUTION).unwrap()).unwrap();
        let runner = crash_child_runner(Path::new(&dir), execution);
        eprintln!("{JOIN_CRASH_REACHED}");
        let _ = runner.divert_under_capsule_profile_for_test(&SmolStr::new(JOIN_STAGE));
        unreachable!("the armed boundary aborts inside the join's transaction");
    }
    for (kill, committed) in [("before_txn_commit", false), ("after_txn_commit", true)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        // THE PREDECESSOR, unarmed: both inputs accepted through the capsule path.
        let execution = {
            let rig = rig_over(None, &path, Some(boot_binding()), true);
            declare_promoted_environment(&rig);
            let runner = join_runner(&rig);
            let reactor = reactor(&rig);
            for input in JOIN_INPUTS {
                accept_input(&rig, &runner, &reactor, input).await;
            }
            rig.execution_id
        };
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", JOIN_CRASH_CELL, "--nocapture"])
            .env(JOIN_CRASH_CHILD, "1")
            .env(JOIN_CRASH_DIR, &path)
            .env(JOIN_CRASH_EXECUTION, execution.to_string())
            .env("KATA_FAULT_INJECT", format!("operational.{kill}"))
            .output()
            .expect("the armed child runs");
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(
            child.status.code().is_none(),
            "{kill}: the child must die on the boundary's abort: {:?}\n{stderr}",
            child.status
        );
        let reached = stderr.find(JOIN_CRASH_REACHED);
        let crashed = stderr.find(&format!("crash point reached: operational.{kill}"));
        assert!(
            matches!((reached, crashed), (Some(reached), Some(crashed)) if reached < crashed),
            "{kill}: the child died at the boundary AFTER presenting the join:\n{stderr}"
        );
        // THE WINDOW, read raw: K3 left nothing of the join, K4 left it accepted.
        let conn = raw(&path.join("operational.db"));
        let (attempts, accepted): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT count(*) FROM attempts WHERE stage_id = ?1),
                        (SELECT count(*) FROM occurrences o JOIN attempts a
                            ON a.attempt_id = o.accepted_attempt_id WHERE a.stage_id = ?1)",
                [JOIN_STAGE],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        drop(conn);
        assert_eq!(
            (attempts, accepted),
            if committed { (1, 1) } else { (0, 0) },
            "{kill}: the crash window"
        );

        // THE SUCCESSOR, over the data directory the crash left.
        let mut rig = rig_over(None, &path, Some(boot_binding()), true);
        rig.execution_id = execution;
        let runner = WorkflowRunner::new_from_program(
            join_program(),
            Arc::clone(&rig.dispatcher),
            execution,
        )
        .expect("the successor's runner builds")
        .with_cache_store(Arc::clone(&rig.store));
        assert!(
            runner
                .divert_under_capsule_profile_for_test(&SmolStr::new(JOIN_STAGE))
                .unwrap_or_else(|error| panic!("{kill}: the successor resolves the join: {error}")),
            "{kill}: resolved main-side"
        );
        assert_eq!(
            join_footprint(&rig),
            (1, 1, vec!["main".to_string()], 0, 0),
            "{kill}: exactly ONE join occurrence and ONE join attempt after the restart"
        );
        assert_eq!(
            join_output(&rig),
            serde_json::json!({ "joined": input_occurrences_hex(&rig) }),
            "{kill}"
        );
        drop(rig);
        drop(dir);
    }
}

// ---------------------------------------------------------------------------
// The DURABLE TIMER, main-side
// ---------------------------------------------------------------------------

const SLEEP_PACK: &str = include_str!("../../../workflows/smoke/sleep-smoke.star");
const SLEEP_STAGE: &str = "nap";
/// `sleep-smoke.star`'s `for_ms`.
const SLEEP_FOR_MS: i64 = 3_000;

/// A pack compiled under `oci` — the profile's own CHECK door.
fn oci_program(pack: &str, file: &str) -> kata_program::execution_program::ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(pack, file, &[]).expect("the pack compiles under oci")
}

fn sleep_program() -> kata_program::execution_program::ExecutionProgram {
    oci_program(SLEEP_PACK, "sleep-smoke.star")
}

/// The runner over `program`, its execution ADMITTED by `put_current_program`.
fn program_runner(
    rig: &Rig,
    program: kata_program::execution_program::ExecutionProgram,
) -> WorkflowRunner {
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(rig.execution_id, &program)
        .expect("the program is retained");
    seed_scratch_head(rig);
    WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
        .expect("the runner builds")
        .with_cache_store(Arc::clone(&rig.store))
}

/// The main's deadline tick, as `run_assignment_deadline_sweep` runs it, every 50 ms on
/// the wall clock — the production tick, so the drive covers the due-wait leg's WIRING.
fn spawn_deadline_ticker(rig: &Rig) -> tokio::task::JoinHandle<()> {
    let dispatcher = Arc::clone(&rig.dispatcher);
    tokio::spawn(async move {
        loop {
            dispatcher
                .run_deadline_sweep_tick_for_test(kata_types::time::now_ms())
                .await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
}

/// [`run_next_capsule`], answering only after `delay`.
async fn run_next_capsule_after(
    rig: &Rig,
    reactor: &kata_workflow::reactor::ResultReactor,
    delay: std::time::Duration,
) -> String {
    tokio::time::sleep(delay).await;
    run_next_capsule(rig, reactor).await
}

/// DRIVE the shipped sleep smoke through `WorkflowRunner::run`, the stub worker answering
/// each capsule `answer_delay` after the previous answer, the deadline tick running
/// beside it. Answers the run's outcome and every stage a capsule was delivered for.
async fn drive_sleep_smoke(
    rig: &Rig,
    answer_delay: std::time::Duration,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<String>,
) {
    declare_promoted_environment(rig);
    let runner = program_runner(rig, sleep_program());
    let reactor = reactor(rig);
    let ticker = spawn_deadline_ticker(rig);
    let mut capsule_stages = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                stage = run_next_capsule_after(rig, &reactor, answer_delay) => {
                    capsule_stages.push(stage);
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    ticker.abort();
    (outcome, capsule_stages)
}

/// The timer's durable facts, read raw: `(attempt id, executor, claim recorded_at_ms, the
/// deadline its PARK frame recorded, the accepting transition's (seq, recorded_at_ms) if
/// accepted, its recorded output)`.
struct TimerFacts {
    attempt: Ulid,
    executor: String,
    claimed_at_ms: i64,
    parked_deadline_ms: i64,
    accepted: Option<(i64, i64)>,
    output: Option<serde_json::Value>,
}

fn timer_facts(rig: &Rig, stage: &str) -> TimerFacts {
    let conn = raw(&rig.op_path);
    let (attempt, executor): (Vec<u8>, String) = conn
        .query_row(
            "SELECT attempt_id, executor FROM attempts WHERE stage_id = ?1",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("{stage} has exactly one attempt: {error}"));
    let attempt = Ulid::from_bytes(attempt.try_into().unwrap());
    let transition = |kind: &str, field: &str| -> Option<(i64, i64, Option<String>)> {
        conn.query_row(
            &format!(
                "SELECT seq, recorded_at_ms, json_extract(payload_json, '$.{field}') \
                   FROM transitions WHERE attempt_id = ?1 AND kind = ?2"
            ),
            rusqlite::params![attempt.to_bytes().as_slice(), kind],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, Option<rusqlite::types::Value>>(2)?
                        .map(|value| match value {
                            rusqlite::types::Value::Integer(value) => value.to_string(),
                            rusqlite::types::Value::Text(value) => value,
                            other => format!("{other:?}"),
                        }),
                ))
            },
        )
        .ok()
    };
    let (_, claimed_at_ms, _) = transition("main_claimed", "assignment").expect("claimed");
    let (_, _, deadline) = transition("main_parked", "wait_deadline_ms").expect("parked");
    let accepted = conn
        .query_row(
            "SELECT t.seq, t.recorded_at_ms, json_extract(t.payload_json, '$.output') \
               FROM occurrences o JOIN transitions t ON t.attempt_id = o.accepted_attempt_id \
                AND t.resulting_state = 'completed' WHERE o.accepted_attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| {
                Ok((
                    (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?),
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .ok();
    TimerFacts {
        attempt,
        executor,
        claimed_at_ms,
        parked_deadline_ms: deadline
            .expect("the park frame carries the deadline")
            .parse()
            .unwrap(),
        accepted: accepted.as_ref().map(|(accepted, _)| *accepted),
        output: accepted.map(|(_, output)| serde_json::from_str(&output).unwrap()),
    }
}

/// `(capsules, commands)` bound to `stage`'s attempts, and how many `completed`
/// transitions they carry — read raw.
fn stage_footprint(rig: &Rig, stage: &str) -> (i64, i64, i64) {
    raw(&rig.op_path)
        .query_row(
            "SELECT
                (SELECT count(*) FROM capsules WHERE occurrence_id IN
                    (SELECT occurrence_id FROM attempts WHERE stage_id = ?1)),
                (SELECT count(*) FROM attempt_commands WHERE attempt_id IN
                    (SELECT attempt_id FROM attempts WHERE stage_id = ?1)),
                (SELECT count(*) FROM transitions WHERE resulting_state = 'completed'
                    AND attempt_id IN (SELECT attempt_id FROM attempts WHERE stage_id = ?1))",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// How many attempts `stage` has, read raw.
fn attempts_of(rig: &Rig, stage: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = ?1",
            [stage],
            |row| row.get(0),
        )
        .unwrap()
}

/// `stage`'s first transition's seq, read raw.
fn first_seq_of(rig: &Rig, stage: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT min(t.seq) FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = ?1",
            [stage],
            |row| row.get(0),
        )
        .unwrap()
}

/// Poll the raw plane until `stage`'s timer is parked.
async fn until_parked(rig: &Rig, stage: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let parked: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT count(*) FROM attempts a JOIN attempt_projection p
                    ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                   AND p.attempt_ordinal = a.attempt_ordinal
                  WHERE a.stage_id = ?1 AND p.state = 'awaiting_timer'",
                [stage],
                |row| row.get(0),
            )
            .unwrap();
        if parked == 1 {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{stage} never parked");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// THE WHOLE DRIVE: under `oci` the shipped sleep smoke completes, and its sleep ran NO
/// process — one `executor = 'main'` attempt, no capsule, no command, no
/// frame delivered for it — was accepted `{"deadline_ms": <its deadline>}` at or after
/// that deadline, and released `after` only then: `after`'s first transition follows the
/// timer's acceptance, and `after` rendered `before`'s output. The drive's own clock says
/// at least the sleep's three seconds passed. Every fact is read raw.
///
/// **Watched red:** with the divert's `Wait(For)` arm refused, the run fails at the sleep.
#[tokio::test]
async fn a_durable_sleep_parks_main_side_and_releases_its_successor_after_the_deadline() {
    let rig = rig();
    let started = std::time::Instant::now();
    let (outcome, capsule_stages) = drive_sleep_smoke(&rig, std::time::Duration::ZERO).await;
    let elapsed = started.elapsed();
    let outputs = outcome.expect("the sleep smoke completes under oci");
    assert_eq!(
        capsule_stages,
        vec!["before".to_string(), "after".to_string()]
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(SLEEP_FOR_MS.unsigned_abs()),
        "the drive took the sleep's length ({elapsed:?})"
    );
    let timer = timer_facts(&rig, SLEEP_STAGE);
    assert_eq!(timer.executor, "main");
    assert_eq!(stage_footprint(&rig, SLEEP_STAGE), (0, 0, 1));
    let (accept_seq, accepted_at_ms) = timer.accepted.expect("the timer was accepted");
    assert!(
        accepted_at_ms >= timer.parked_deadline_ms,
        "accepted at {accepted_at_ms}, not before its deadline {}",
        timer.parked_deadline_ms
    );
    assert_eq!(
        timer.output,
        Some(serde_json::json!({ "deadline_ms": timer.parked_deadline_ms }))
    );
    assert!(
        first_seq_of(&rig, "after") > accept_seq,
        "after ran after the acceptance"
    );
    assert_eq!(
        outputs[SLEEP_STAGE],
        serde_json::json!({ "deadline_ms": timer.parked_deadline_ms })
    );
    assert_eq!(
        outputs["after"]["parsed"]["carried"], "before-value",
        "{outputs:?}"
    );
    println!(
        "SLEEP-DRIVE elapsed={elapsed:?} claimed_at={} deadline={} accepted_at={accepted_at_ms} \
         late_by_ms={}",
        timer.claimed_at_ms,
        timer.parked_deadline_ms,
        accepted_at_ms - timer.parked_deadline_ms
    );
    drop(rig.dir);
}

/// THE ANCHOR IS THE CLAIM'S RECORDED INSTANT: the timer's durable deadline (its park
/// frame's, read raw) is exactly its claiming transition's `recorded_at_ms` plus the
/// sleep — even though the execution STARTED well before it (the stub worker holds
/// `before`'s answer 400 ms), so an anchor at any earlier instant is told apart.
///
/// **Watched red:** with `park_timer` anchoring at the execution's start stamp
/// (`WaitDeadline::At { epoch_ms: <execution start> + for_ms }`), the deadline lands ≥ 400
/// ms before the claim's `recorded_at_ms + for_ms`.
#[tokio::test]
async fn the_anchor_is_the_claims_recorded_at() {
    let rig = rig();
    let (outcome, _) = drive_sleep_smoke(&rig, std::time::Duration::from_millis(400)).await;
    outcome.expect("the sleep smoke completes under oci");
    let timer = timer_facts(&rig, SLEEP_STAGE);
    assert_eq!(
        timer.parked_deadline_ms,
        timer.claimed_at_ms + SLEEP_FOR_MS,
        "the deadline is the claim's recorded instant plus the sleep"
    );
    drop(rig.dir);
}

/// A RESTART BEFORE THE DEADLINE DOES NOT FIRE; ONE AFTER IT FIRES ONCE. A timer parked
/// by one main; a SECOND main's planes over the same data directory (the restart): its
/// deadline tick one millisecond before the durable deadline accepts nothing; its runner's
/// re-submission of the stage — what a resume does, since the claim folds `Pending` —
/// converges on the live timer (`AlreadyLive`, treated as in flight: the divert answers
/// resolved and writes nothing); its tick AT the deadline accepts it; and a later tick
/// accepts nothing more. Exactly one attempt and one `completed` transition, read raw.
///
/// **Watched red:** (a) with the tick's due-wait leg removed, the tick at the deadline
/// accepts nothing; (b) with `park_timer` treating `AlreadyLive` as a refusal, the
/// resumed re-submission errors.
#[tokio::test]
async fn a_timer_restarted_before_its_deadline_waits_and_after_it_fires_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let execution = {
        let rig = rig_over(None, &path, Some(boot_binding()), true);
        let runner = program_runner(&rig, sleep_program());
        assert!(
            runner
                .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
                .expect("the timer parks"),
            "resolved main-side"
        );
        rig.execution_id
    };
    let mut rig = rig_over(None, &path, Some(boot_binding()), true);
    rig.execution_id = execution;
    let deadline = timer_facts(&rig, SLEEP_STAGE).parked_deadline_ms;
    let at = |ms: i64| u64::try_from(ms).unwrap();

    rig.dispatcher
        .run_deadline_sweep_tick_for_test(at(deadline - 1))
        .await;
    assert_eq!(
        timer_facts(&rig, SLEEP_STAGE).accepted,
        None,
        "not before its deadline"
    );

    let resumed =
        WorkflowRunner::new_from_program(sleep_program(), Arc::clone(&rig.dispatcher), execution)
            .expect("the successor's runner builds");
    assert!(
        resumed
            .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
            .expect("a resumed re-submission is the timer in flight, not a refusal"),
        "resolved main-side"
    );
    assert_eq!(attempts_of(&rig, SLEEP_STAGE), 1, "no second claim");
    assert_eq!(
        timer_facts(&rig, SLEEP_STAGE).parked_deadline_ms,
        deadline,
        "the resume did not re-anchor the deadline"
    );

    rig.dispatcher
        .run_deadline_sweep_tick_for_test(at(deadline))
        .await;
    assert!(
        timer_facts(&rig, SLEEP_STAGE).accepted.is_some(),
        "fires at its deadline"
    );
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(at(deadline + 10_000))
        .await;
    assert_eq!(attempts_of(&rig, SLEEP_STAGE), 1);
    assert_eq!(stage_footprint(&rig, SLEEP_STAGE).2, 1, "fires ONCE");
    drop(rig);
    drop(dir);
}

/// A PAST `Until` FIRES ON THE FIRST TICK: a sleep until an instant long gone is parked
/// with exactly that deadline and accepted by the very next tick, `{"deadline_ms": 1}`.
///
/// **Watched red:** with the tick's due-wait leg removed, it stays parked.
#[tokio::test]
async fn a_past_until_fires_on_the_first_tick() {
    let rig = rig();
    let program = oci_program(
        "a = stage(id = \"a\", agent = \"shell\", run = \"true\")\n\
         nap = sleep(id = \"nap\", until_ms = 1, depends_on = [a])\n\
         workflow(\"until-pack\", root = [a])\n",
        "until.star",
    );
    let runner = program_runner(&rig, program);
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
            .expect("the timer parks"),
    );
    assert_eq!(timer_facts(&rig, SLEEP_STAGE).parked_deadline_ms, 1);
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(kata_types::time::now_ms())
        .await;
    let timer = timer_facts(&rig, SLEEP_STAGE);
    assert!(timer.accepted.is_some(), "the first tick accepts it");
    assert_eq!(timer.output, Some(serde_json::json!({ "deadline_ms": 1 })));
    drop(rig.dir);
}

/// THE TICK BURSTS: after a pause the deadline interval fires its missed ticks
/// back to back. Two ticks CONCURRENTLY and a third right after, all past the deadline,
/// accept the timer exactly once: one `completed` transition, read raw.
///
/// **Not watched red by the premise alone, stated:** with `DueWait` answering `true` for
/// any state this cell stays GREEN (measured), because a resolved timer is excluded
/// before any premise is read — the due read filters on the parked state, and the
/// resolution clears `wait_deadline_ms`. The premise's own exactly-once is pinned where it
/// can be isolated: `operational_main_attempt.rs`'s
/// `back_to_back_due_sweeps_resolve_a_wait_exactly_once`. This cell pins the tick-level
/// composition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn back_to_back_burst_ticks_accept_a_due_timer_once() {
    let rig = rig();
    let runner = program_runner(&rig, sleep_program());
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
            .expect("the timer parks"),
    );
    let due = u64::try_from(timer_facts(&rig, SLEEP_STAGE).parked_deadline_ms + 1).unwrap();
    let (first, second) = (Arc::clone(&rig.dispatcher), Arc::clone(&rig.dispatcher));
    let (a, b) = tokio::join!(
        tokio::spawn(async move { first.run_deadline_sweep_tick_for_test(due).await }),
        tokio::spawn(async move { second.run_deadline_sweep_tick_for_test(due + 1).await }),
    );
    a.unwrap();
    b.unwrap();
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(due + 2)
        .await;
    assert_eq!(stage_footprint(&rig, SLEEP_STAGE).2, 1, "one acceptance");
    let resolutions: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM transitions WHERE kind = 'main_resolved'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(resolutions, 1, "one resolution");
    drop(rig.dir);
}

/// CANCEL MID-WAIT: the drive parks the sleep, the execution's main-side cancel
/// (`Dispatcher::cancel_parked_main_waits`, the arm `WorkflowExecutor::cancel` calls)
/// resolves it `cancelled`, the run ends without completing, and `after` is NEVER
/// submitted — no attempt, no capsule — not even once the deadline tick has run past the
/// sleep's deadline. Read raw.
///
/// **Watched red:** with `cancel_parked_main_waits` resolving nothing (answering `Ok(0)`),
/// the timer fires at its deadline and `after` runs.
#[tokio::test]
async fn cancel_mid_wait_settles_cancelled_and_never_submits_the_successor() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = program_runner(&rig, sleep_program());
    let reactor = reactor(&rig);
    let ticker = spawn_deadline_ticker(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut cancelled = None;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                _stage = run_next_capsule(&rig, &reactor) => {}
                () = until_parked(&rig, SLEEP_STAGE), if cancelled.is_none() => {
                    cancelled = Some(
                        rig.dispatcher
                            .cancel_parked_main_waits(rig.execution_id, "operator cancel")
                            .expect("the cancel resolves the parked wait"),
                    );
                }
            }
        }
    })
    .await
    .expect("the run ends");
    // Past the deadline, the tick still accepts nothing: the wait is terminal.
    let deadline = timer_facts(&rig, SLEEP_STAGE).parked_deadline_ms;
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(u64::try_from(deadline + 10_000).unwrap())
        .await;
    ticker.abort();
    assert_eq!(cancelled, Some(1), "the cancel settled the one parked wait");
    assert!(
        outcome.is_err(),
        "a cancelled wait does not complete the run: {outcome:?}"
    );
    assert_eq!(
        last_transition(&rig, timer_facts(&rig, SLEEP_STAGE).attempt).0,
        "cancelled"
    );
    assert_eq!(timer_facts(&rig, SLEEP_STAGE).accepted, None);
    assert_eq!(
        attempts_of(&rig, "after"),
        0,
        "the successor was never submitted"
    );
    assert_eq!(stage_footprint(&rig, "after"), (0, 0, 0));
    drop(rig.dir);
}

/// AN ABANDONED MAIN WAIT IS SETTLED: a timer parked in an execution that then LATCHES
/// its outcome (`terminalizing`: its runner has returned, its closeout not yet published)
/// is resolved `cancelled` by the deadline tick — and only then does the chain witness
/// every stage terminal, so the closeout can finish. Read raw.
///
/// **Watched red:** with the tick's abandoned-wait leg omitted, the wait stays
/// `awaiting_timer` under the terminalizing execution.
#[tokio::test]
async fn an_abandoned_main_wait_is_settled_and_the_execution_finishes() {
    let rig = rig();
    let runner = program_runner(&rig, sleep_program());
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
            .expect("the timer parks"),
    );
    rig.db
        .begin_terminalization_with_cleanup(
            rig.execution_id,
            kata_core::LifecycleState::Failed,
            b"{\"code\":\"failed\",\"message\":\"a sibling failed\"}",
            "converge_absent",
        )
        .expect("the outcome latches");
    // BEFORE its deadline: the leg is abandonment, not due-ness.
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(kata_types::time::now_ms())
        .await;
    let timer = timer_facts(&rig, SLEEP_STAGE);
    let (state, reason) = last_transition(&rig, timer.attempt);
    assert_eq!(state, "cancelled", "{reason}");
    assert!(reason.contains("latched its outcome"), "{reason}");
    assert_eq!(timer.accepted, None);
    rig.db.complete_execution_cleanup(rig.execution_id).unwrap();
    rig.db.finish_terminalization(rig.execution_id).unwrap();
    let lifecycle: String = raw(&rig.op_path)
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            [rig.execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lifecycle, "failed", "the closeout finished");
    drop(rig.dir);
}

/// GRACEFUL SHUTDOWN WITH A PARKED TIMER DETACHES: a run whose only open work is a parked
/// main timer, on a main that has begun its ordered shutdown (whose deadline sweep — the
/// timer's only waker — is stopped: no tick runs in this cell), hands the run back
/// (`AdmissionClosed`) within a few chain-wake budgets instead of holding the drain until
/// the deadline. Nothing is terminalized: the timer is still parked, read raw.
///
/// **Watched red:** with `detach_loses_nothing` reading the live-work registry
/// alone (which excludes main attempts), no open work is seen, the run keeps waiting, and
/// the cell's 60 s budget expires (generous on purpose: the nap is ten minutes, so any
/// budget under it separates a detach from a held drain).
#[tokio::test]
async fn graceful_shutdown_with_a_parked_timer_detaches() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = program_runner(
        &rig,
        oci_program(
            "a = stage(id = \"a\", agent = \"shell\", run = \"true\")\n\
         nap = sleep(id = \"nap\", for_ms = 600000, depends_on = [a])\n\
         workflow(\"long-nap\", root = [a])\n",
            "long-nap.star",
        ),
    );
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut stopping = false;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                _stage = run_next_capsule(&rig, &reactor) => {}
                () = until_parked(&rig, SLEEP_STAGE), if !stopping => {
                    rig.dispatcher.begin_graceful_shutdown();
                    stopping = true;
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
    let parked: String = raw(&rig.op_path)
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal WHERE a.stage_id = ?1",
            [SLEEP_STAGE],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(parked, "awaiting_timer", "detaching terminalized nothing");
    drop(rig.dir);
}

/// AN EXPIRED WAIT FIRES ON THE FIRST PASS AFTER THE GATE OPENS, not one
/// heartbeat later. A timer whose deadline passed while its main was down; a restarted
/// main whose dispatcher is FENCED for startup recovery runs the production
/// `run_assignment_deadline_sweep` on a 600 s interval: while the gate is closed the timer
/// stays parked, and within 30 s of the gate's release — a twentieth of the interval — it
/// is accepted. Read raw. The budget is the property only as a fraction of the interval,
/// so both are wide enough that a loaded host's FULL-sync commits cannot exhaust it.
///
/// **Watched red:** without the due-wait pass at gate-open, the first pass is the
/// interval's first real tick, 600 s later, and the 30 s budget expires.
#[tokio::test]
async fn an_expired_wait_resolves_on_the_first_pass_after_the_gate_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let program = oci_program(
        "a = stage(id = \"a\", agent = \"shell\", run = \"true\")\n\
         nap = sleep(id = \"nap\", for_ms = 50, depends_on = [a])\n\
         workflow(\"short-nap\", root = [a])\n",
        "short-nap.star",
    );
    let (execution, op_path) = {
        let rig = rig_over(None, &path, Some(boot_binding()), true);
        let runner = program_runner(&rig, program);
        assert!(
            runner
                .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
                .expect("the timer parks"),
        );
        (rig.execution_id, rig.op_path.clone())
    };
    // The main is DOWN past the deadline.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let store =
        Arc::new(kata_core::store::SqliteWorkflowStore::open(path.join("workflow.db")).unwrap());
    let db = Arc::new(OperationalDb::open_with_cas(&op_path, store.shared_cas()).unwrap());
    let (dispatcher, guard) = Dispatcher::new(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        )),
        kata_core::InFlightLedger::in_memory(),
    )
    .with_execution_lifecycle(kata_workflow::execution_lifecycle::ExecutionLifecycleFace::new(db))
    .with_startup_recovery_fence()
    .expect("the fence arms before the dispatcher is shared");
    let dispatcher = Arc::new(dispatcher);
    let sweep = tokio::spawn(
        Arc::clone(&dispatcher).run_assignment_deadline_sweep(std::time::Duration::from_secs(600)),
    );
    let accepted = || -> bool {
        raw(&op_path)
            .query_row(
                "SELECT count(*) FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
                  WHERE a.stage_id = ?1 AND a.execution_id = ?2 AND t.resulting_state = 'completed'",
                rusqlite::params![SLEEP_STAGE, execution.to_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            == 1
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !accepted(),
        "nothing is resolved while startup recovery holds the gate"
    );
    let opened = std::time::Instant::now();
    guard.release(&dispatcher).expect("the gate opens");
    while !accepted() {
        assert!(
            opened.elapsed() < std::time::Duration::from_secs(30),
            "the expired timer was not resolved within 30 s of the gate opening"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    println!("GATE-OPEN-CELL gate_open_to_accept={:?}", opened.elapsed());
    sweep.abort();
    drop(dir);
}

/// THE RECOVERY SLEEP COHORT CARRIES A PARKED MAIN TIMER. With one engine every
/// durable sleep IS a main timer, so the cohort targets it — a capture around the
/// timer the divert actually parked records that
/// attempt with the row's own claim-anchored `wait_deadline_ms`, and the restored main
/// resumes it from its row (`recovery-checkpoint-live` proves the resume end to end).
#[tokio::test]
async fn recovery_capture_carries_a_parked_main_timer_with_its_deadline() {
    let rig = rig();
    let runner = program_runner(&rig, sleep_program());
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new(SLEEP_STAGE))
            .expect("the timer parks"),
    );
    let facts = timer_facts(&rig, SLEEP_STAGE);
    let population = kata_core::operational::inspect_recovery_sleep_population(
        &raw(&rig.op_path),
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .expect("a parked main timer is the durable-sleep cohort");
    let sleeps: Vec<_> = population.executions.values().flatten().collect();
    assert_eq!(sleeps.len(), 1, "{sleeps:?}");
    assert_eq!(sleeps[0].attempt_id, facts.attempt);
    assert_eq!(sleeps[0].stage_id, SLEEP_STAGE);
    assert_eq!(sleeps[0].wait_deadline_ms, facts.parked_deadline_ms);
    drop(rig.dir);
}

/// The only attempt's `(attempt_id, latest lifecycle state)`, raw.
const GATE_PACK: &str = include_str!("../../../workflows/examples/human-gate-approval.star");
const GATE_STAGE: &str = "deploy";

/// `(attempts, dispatch commands)` of `stage`, raw.
fn attempts_and_commands_of(rig: &Rig, stage: &str) -> (i64, i64) {
    raw(&rig.op_path)
        .query_row(
            "SELECT count(*), (SELECT count(*) FROM attempt_commands c \
                JOIN attempts b ON b.attempt_id = c.attempt_id WHERE b.stage_id = ?1) \
               FROM attempts a WHERE a.stage_id = ?1",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the stage's footprint")
}

/// A PARKED GATE ACROSS A WHOLE-RUNNER RESTART.
/// `WorkflowRunner::run` drives the shipped gated pack on `oci` until `deploy` PARKS,
/// with a stub worker running every delivered capsule; the runner and every plane are
/// dropped; a new process's planes and a NEW runner resume the same execution. The resumed
/// run IDLES on the gate — one `deploy` attempt, still parked, no frame delivered, no
/// re-run of `prepare` — until the operator approves; then exactly one `deploy` dispatch
/// is delivered and the run completes with both stages' outputs. Counts read raw.
///
/// **Watched red** only under a COMPOSITE mutation — the resumed fold ignoring the park
/// (`apply_event`'s `AwaitingApproval` arm returning early, so the stage is re-submitted)
/// AND the gated path reading the adoption read instead of the park (`authorize`): a
/// second parked `deploy` attempt, `(2, 0)`. Either defence alone keeps it green — the
/// fold pauses the stage so nothing is re-presented, and a re-presentation re-reads the
/// park — so this cell is the whole-runner COMPOSITION proof; each defence has its own
/// killing cell (`re_presenting_a_gated_occurrence_never_dispatches` for the second).
#[tokio::test]
async fn a_parked_gate_survives_a_whole_runner_restart_and_runs_once_approved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let program = oci_program(GATE_PACK, "human-gate-approval.star");
    let reopen = || rig_over(None, &path, Some(boot_binding()), true);

    // FIRST MAIN: run until the gate parks, answering `prepare`'s capsule.
    let execution = {
        let rig = reopen();
        declare_promoted_environment(&rig);
        let runner = program_runner(&rig, program.clone());
        rig.dispatcher
            .execution_lifecycle()
            .mark_running_after_admission(rig.execution_id)
            .expect("the execution runs");
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                if attempts_of(&rig, GATE_STAGE) == 1 {
                    break;
                }
                tokio::select! {
                    outcome = &mut run => panic!("the run ended before the gate parked: {outcome:?}"),
                    answered = run_next_capsule(&rig, &reactor) => assert_eq!(answered, "prepare"),
                    () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                }
            }
        })
        .await
        .expect("the gate parks");
        rig.execution_id
    };

    // THE SUCCESSOR: new planes, a new runner, the same execution.
    let mut rig = reopen();
    rig.execution_id = execution;
    let (attempt, state) = raw(&rig.op_path)
        .query_row(
            "SELECT a.attempt_id, p.state FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal WHERE a.stage_id = ?1",
            [GATE_STAGE],
            |row| {
                Ok((
                    Ulid::from_bytes(row.get::<_, Vec<u8>>(0)?.try_into().unwrap()),
                    row.get::<_, String>(1)?,
                ))
            },
        )
        .expect("the parked gate");
    assert_eq!(state, "awaiting_approval");
    let prepare_before = attempts_and_commands_of(&rig, "prepare");
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), execution)
        .expect("the successor's runner builds")
        .with_cache_store(Arc::clone(&rig.store));
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let idle = tokio::time::timeout(std::time::Duration::from_secs(3), &mut run).await;
    assert!(idle.is_err(), "the resumed run waits on the gate: {idle:?}");
    let early = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        rig.worker_side.recv_frame(),
    )
    .await;
    assert!(
        early.is_err(),
        "nothing is delivered before the approve: {early:?}"
    );
    assert_eq!(
        attempts_and_commands_of(&rig, GATE_STAGE),
        (1, 0),
        "one parked attempt"
    );
    assert_eq!(
        attempts_and_commands_of(&rig, "prepare"),
        prepare_before,
        "prepare is not re-run"
    );

    rig.dispatcher
        .approve_capsule_gate(
            attempt,
            &kata_types::approval::ApprovalPrincipal::Token {
                issued_for: "operator-cli".to_owned(),
            },
        )
        .await
        .expect("the gate is approved on the successor");
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                answered = run_next_capsule(&rig, &reactor) => assert_eq!(answered, GATE_STAGE),
            }
        }
    })
    .await
    .expect("the run finishes after the approve")
    .expect("the run completes");
    assert_eq!(
        outputs.keys().map(SmolStr::as_str).collect::<Vec<_>>(),
        vec![GATE_STAGE, "prepare"]
    );
    assert_eq!(
        attempts_and_commands_of(&rig, GATE_STAGE),
        (1, 1),
        "exactly one deploy attempt and one dispatch command"
    );
    drop(rig);
    drop(dir);
}

// -- THE EXIT STATUS UNDER `oci` ---------------------------------------------------------
//
// The main judges a capsule process's `exit_code` at the capsule's acceptance with the
// one predicate (`ShellExitPolicy::judge_exit`; `ShellExitPolicy::ZeroSuccess` is the
// default). Recording the exit code without judging it would let a stage that exited 3
// COMPLETE and release its successor.

/// `ok` exits 0, `boom` prints to both streams and EXITS 3, `after` depends on `boom`.
const EXIT_STATUS_PACK: &str = "ok = stage(id = \"ok\", agent = \"shell\", run = \"echo fine\")\n\
     boom = stage(id = \"boom\", agent = \"shell\", \
     run = \"echo boom-said; echo boom-err >&2; exit 3\", depends_on = [ok])\n\
     after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [boom])\n\
     workflow(\"exit-status\", root = [ok])\n";

/// `gate` DECLARES `exit_policy = "content"` and exits 3; `after` depends on it.
const EXIT_CONTENT_PACK: &str = "gate = stage(id = \"gate\", agent = \"shell\", \
     run = \"echo gate-said; exit 3\", exit_policy = \"content\")\n\
     after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [gate])\n\
     workflow(\"exit-content\", root = [gate])\n";

/// DRIVE `program` through `WorkflowRunner::run` — the production submit path, every
/// capsule answered by the stub worker running its argv with the host's `sh` and reporting
/// the real exit status.
async fn drive_program(
    rig: &Rig,
    program: kata_program::execution_program::ExecutionProgram,
) -> kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>> {
    declare_promoted_environment(rig);
    let runner = program_runner(rig, program);
    let reactor = reactor(rig);
    let run = runner.run();
    tokio::pin!(run);
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                _stage = run_next_capsule(rig, &reactor) => {}
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget")
}

/// `(occurrences of stage accepted, completed transitions of stage)`, read raw.
fn acceptance_facts(rig: &Rig, stage: &str) -> (i64, i64) {
    raw(&rig.op_path)
        .query_row(
            "SELECT
                (SELECT count(*) FROM occurrences WHERE accepted_attempt_id IN
                    (SELECT attempt_id FROM attempts WHERE stage_id = ?1)),
                (SELECT count(*) FROM transitions WHERE resulting_state = 'completed'
                    AND attempt_id IN (SELECT attempt_id FROM attempts WHERE stage_id = ?1))",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// The one attempt id of `stage`, read raw.
fn attempt_of(rig: &Rig, stage: &str) -> Ulid {
    let id: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT attempt_id FROM attempts WHERE stage_id = ?1",
            [stage],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("{stage} has exactly one attempt: {error}"));
    Ulid::from_bytes(id.try_into().unwrap())
}

/// A CAPSULE THAT EXITS 3 FAILS ITS STAGE under `oci`, and its successor is never submitted. Driven
/// through the production submit path (`WorkflowRunner::run` → divert → capsule submit → the
/// reactor's `CompletedCapsule` arm); read raw: `ok` accepted; `boom`'s ONE attempt is `failed`
/// with the `ShellNonzeroExit` reason (`exit_code=3`, the stderr tail) and the PERFORMED BUT FAILED
/// verdict, its occurrence accepts NO outcome and no transition of it is `completed`; `after` has
/// no attempt at all; the run does not complete.
///
/// **Watched red:** with the reactor's exit judgement removed (the pre-fix arm), `boom`
/// is ACCEPTED `completed` with `exit_code: 3` in its outcome, `after` runs, and the run
/// completes.
#[tokio::test]
async fn a_capsule_exiting_nonzero_fails_its_stage_and_never_releases_the_successor() {
    let rig = rig();
    let outcome = drive_program(&rig, oci_program(EXIT_STATUS_PACK, "exit-status.star")).await;
    assert!(
        outcome.is_err(),
        "a stage that exited 3 does not complete the run: {outcome:?}"
    );
    assert_eq!(
        acceptance_facts(&rig, "ok"),
        (1, 1),
        "ok exited 0 and completed"
    );
    let (state, reason) = last_transition(&rig, attempt_of(&rig, "boom"));
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains(kata_types::workflow::SHELL_NONZERO_EXIT_ERROR_PREFIX)
            && reason.contains("exit_code=3")
            && reason.contains("boom-err")
            && reason.contains("PERFORMED BUT FAILED"),
        "the recorded reason is the exit failure and the verdict: {reason}"
    );
    assert_eq!(
        acceptance_facts(&rig, "boom"),
        (0, 0),
        "no outcome is accepted and nothing of boom completed"
    );
    assert_eq!(
        attempts_of(&rig, "after"),
        0,
        "the successor was never submitted"
    );
    drop(rig.dir);
}

/// A DECLARED `exit_policy = "content"` stage that exits 3 COMPLETES under `oci` — the
/// opt-out means the exit code is content: it rides the
/// accepted outcome, and the successor runs. Read raw.
///
/// **Watched red:** with `ShellExitPolicy::judge_exit` terminalizing every nonzero exit
/// regardless of the policy, `gate` fails and `after` never runs.
#[tokio::test]
async fn a_content_policy_capsule_exiting_nonzero_completes_and_releases_the_successor() {
    let rig = rig();
    let outcome = drive_program(&rig, oci_program(EXIT_CONTENT_PACK, "exit-content.star")).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(acceptance_facts(&rig, "gate"), (1, 1));
    let exit_code: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.output.exit_code') FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = 'gate' AND t.resulting_state = 'completed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        exit_code, 3,
        "the exit code is content in the accepted outcome"
    );
    assert_eq!(acceptance_facts(&rig, "after"), (1, 1), "the successor ran");
    drop(rig.dir);
}

/// A capsule whose provider reported NO exit status (a signal death, a runtime kill) is
/// judged as `SIGNALLED_EXIT_CODE`, `-1` — so under the
/// default policy it FAILS, `exit_code=-1`, and its result is not adopted. Read raw.
///
/// **Watched red:** judging `None` as `0` (`unwrap_or(0)`) — and, separately, with the
/// reactor's exit judgement removed — the attempt is accepted `completed`.
#[tokio::test]
async fn a_capsule_reporting_no_exit_status_fails_under_the_default_policy() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    let mut signalled = completed_capsule(&rig, &frame, empty_tree_result());
    if let kata_transport::types::WorkerMessage::CompletedCapsule { exit_code, .. } = &mut signalled
    {
        *exit_code = None;
    }
    reactor(&rig)
        .handle_message_for_test(signalled)
        .expect("a judged exit is the attempt's outcome, not a frame error");
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "failed", "{reason}");
    assert!(reason.contains("exit_code=-1"), "{reason}");
    let accepted: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted, 0, "nothing was accepted");
    drop(rig.dir);
}

/// An exit failure reported while an OPERATOR STOP stands against the attempt is recorded
/// `cancelled` — the standing-stop rule — not `failed`. Read raw.
///
/// **Watched red:** with `settle_capsule_attempt`'s standing-stop arm answering `failed`,
/// the attempt is `failed`.
#[tokio::test]
async fn an_exit_failure_under_a_standing_stop_is_recorded_cancelled() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    rig.db
        .record_stop_request(
            frame.attempt_id,
            frame.lease_epoch,
            frame.placed_on.as_str(),
            "operator stop",
        )
        .expect("the durable ask, as `WorkflowExecutor::cancel` writes it");
    let mut exited = completed_capsule(&rig, &frame, empty_tree_result());
    if let kata_transport::types::WorkerMessage::CompletedCapsule { exit_code, .. } = &mut exited {
        *exit_code = Some(3);
    }
    reactor(&rig)
        .handle_message_for_test(exited)
        .expect("a judged exit is the attempt's outcome");
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "cancelled", "{reason}");
    assert!(reason.contains("exit_code=3"), "{reason}");
    drop(rig.dir);
}

/// The exit judgement reads the stage's exit policy off the execution's DURABLE program,
/// and refuses when that program is not the one the capsule's occurrence was authorized
/// under: a policy from another program is not this attempt's policy. The stored program
/// is swapped, with a raw writer, for the same pack under another description — same
/// stage, same exit policy, another hash — so the hash comparison is the only thing that
/// can refuse. Read raw: the frame is refused, and the attempt is neither accepted nor
/// completed.
///
/// **Watched red:** with `capsule_stage_exit_policy`'s program-hash comparison disabled, the
/// swapped program's policy judges the exit 0 a success and the handler answers `Ok(())`
/// instead of refusing the frame.
#[tokio::test]
async fn the_exit_judgement_refuses_a_program_that_is_not_the_occurrences() {
    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    // The pack's own description, read out of it, so the cell does not re-spell it.
    let description = SHIPPED_PACK
        .split_once("description = \"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(description, _)| description)
        .expect("the premise: the pack declares a description");
    let swapped = compile_starlark_execution_program(
        &SHIPPED_PACK.replace(description, "another program with the same stage"),
        "sandbox-smoke-shell-offline.star",
        &[],
    )
    .expect("the swapped pack compiles");
    assert_ne!(
        swapped.program_hash,
        shipped_program().program_hash,
        "the premise: another program"
    );
    let rewritten = rusqlite::Connection::open(&rig.op_path)
        .expect("a raw writer")
        .execute(
            "UPDATE programs SET program_hash = ?1, program_json = ?2 WHERE execution_id = ?3",
            rusqlite::params![
                swapped.program_hash.0.as_slice(),
                serde_json::to_vec(&swapped).unwrap(),
                rig.execution_id.to_bytes().as_slice()
            ],
        )
        .expect("the stored program is swapped");
    assert_eq!(rewritten, 1);

    let refusal = reactor(&rig)
        .handle_message_for_test(completed_capsule(&rig, &frame, empty_tree_result()))
        .expect_err("a completion is not judged against another program's policy")
        .to_string();
    assert!(
        refusal.contains("was authorized under program")
            && refusal.contains(&swapped.program_hash.to_string()),
        "{refusal}"
    );
    assert_eq!(
        last_transition(&rig, frame.attempt_id).0,
        "dispatched",
        "nothing was recorded against the attempt"
    );
    let accepted: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted, 0, "nothing was accepted");
    drop(rig.dir);
}

// -- THE CAPTURE UNDER `oci` -------------------------------------------------------------
//
// A provider's `truncated` flag recorded in the accepted outcome but never judged would let
// a stage whose stdout overran the provider's per-stream capture bound COMPLETE with a
// silently shortened `content` and release its successor. The main judges it at the
// capsule's acceptance, before the exit status, with the one capture predicate
// (`judge_provider_capture`).

/// `ok` prints a line; `big` prints ONE BYTE MORE than its AUTHORED combined capture
/// bound and exits 0; `after` depends on `big`.
const TRUNCATED_CAPTURE_PACK: &str = "ok = stage(id = \"ok\", agent = \"shell\", run = \"echo fine\")\n\
     big = stage(id = \"big\", agent = \"shell\", \
     run = \"yes | head -c 1048577\", output_bytes = 1048576, depends_on = [ok])\n\
     after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [big])\n\
     workflow(\"truncated-capture\", root = [ok])\n";

/// `full` prints EXACTLY the provider's per-stream capture bound — not truncated — and
/// `after` depends on it.
const FULL_CAPTURE_PACK: &str = "full = stage(id = \"full\", agent = \"shell\", \
     run = \"yes | head -c 1048576\", output_bytes = 1048576)\n\
     after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [full])\n\
     workflow(\"full-capture\", root = [full])\n";

/// A CAPSULE WHOSE CAPTURE WAS TRUNCATED FAILS ITS STAGE under `oci`, and its successor is never
/// submitted. Driven through the production submit path (`WorkflowRunner::run` → divert → capsule
/// submit → the reactor's `CompletedCapsule` arm), the stub worker bounding each stream as a
/// provider does. Read raw: `ok` accepted; `big`'s ONE attempt is `failed` with the truncation
/// reason and the PERFORMED BUT FAILED verdict, its occurrence accepts NO outcome and no transition
/// of it is `completed`; `after` has no attempt at all; the run does not complete.
///
/// **Watched red:** with the capture judgement removed from
/// `ShellExitPolicy::judge_provider_completion` (the pre-fix acceptance), `big` is ACCEPTED
/// `completed` with `truncated: true` in its outcome, `after` runs, and the run completes.
#[tokio::test]
async fn a_capsule_reporting_a_truncated_capture_fails_its_stage_and_never_releases_the_successor()
{
    let rig = rig();
    let outcome = drive_program(
        &rig,
        oci_program(TRUNCATED_CAPTURE_PACK, "truncated-capture.star"),
    )
    .await;
    assert!(
        outcome.is_err(),
        "a stage whose capture was truncated does not complete the run: completed stages {:?}",
        outcome
            .as_ref()
            .map(|outputs| outputs.keys().collect::<Vec<_>>())
    );
    assert_eq!(acceptance_facts(&rig, "ok"), (1, 1), "ok completed");
    let (state, reason) = last_transition(&rig, attempt_of(&rig, "big"));
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains(kata_types::workflow::SHELL_CAPTURE_TRUNCATED_MARKER)
            && reason.contains(kata_types::workflow::CAPSULE_CAPTURE_PROVIDER)
            && reason.contains("PERFORMED BUT FAILED"),
        "the recorded reason is the truncation failure and the verdict: {reason}"
    );
    assert_eq!(
        acceptance_facts(&rig, "big"),
        (0, 0),
        "no outcome is accepted and nothing of big completed"
    );
    assert_eq!(
        attempts_of(&rig, "after"),
        0,
        "the successor was never submitted"
    );
    drop(rig.dir);
}

/// A capture of EXACTLY the provider's per-stream bound is not truncated, and the stage
/// COMPLETES and releases its successor under `oci`. Read raw (the 1 MiB outcome is
/// offloaded to the output plane, so the acceptance is read off the occurrence and the
/// `completed` transition, and the capture's wholeness off the run's own outputs).
///
/// **Watched red:** with the stub bounding at `<` rather than `<=` (a capture AT the bound
/// reported truncated), `full` fails and `after` never runs.
#[tokio::test]
async fn a_capsule_capture_at_the_bound_completes_and_releases_the_successor() {
    let rig = rig();
    let outputs = drive_program(&rig, oci_program(FULL_CAPTURE_PACK, "full-capture.star"))
        .await
        .expect("a capture at the bound completes the run");
    assert_eq!(acceptance_facts(&rig, "full"), (1, 1));
    assert_eq!(acceptance_facts(&rig, "after"), (1, 1), "the successor ran");
    let content = outputs["full"]["content"].as_str().unwrap_or_default();
    assert_eq!(
        content.len(),
        1 << 20,
        "the accepted content is the whole capture: {}",
        outputs["full"]
    );
    drop(rig.dir);
}

/// A truncated capture FAILS a stage that EXITED 0 — the capture is judged before and
/// apart from the exit (no exit policy exempts it; the `content`
/// arm is pinned on the predicate itself in `kata-types`) — and under a standing operator
/// stop the same failure is recorded `cancelled`, the standing-stop rule. Read raw.
///
/// **Watched red:** with the capture judgement removed, the first attempt is accepted
/// `completed`.
#[tokio::test]
async fn a_truncated_capture_fails_whatever_the_policy_and_is_cancelled_under_a_stop() {
    let unstopped = rig();
    let frame = dispatched_capsule_attempt(&unstopped).await;
    let mut truncated_completion = completed_capsule(&unstopped, &frame, empty_tree_result());
    if let kata_transport::types::WorkerMessage::CompletedCapsule {
        capture_exceeded, ..
    } = &mut truncated_completion
    {
        *capture_exceeded = true;
    }
    reactor(&unstopped)
        .handle_message_for_test(truncated_completion)
        .expect("a judged capture is the attempt's outcome, not a frame error");
    let (state, reason) = last_transition(&unstopped, frame.attempt_id);
    assert_eq!(state, "failed", "exited 0 and still failed: {reason}");
    assert!(
        reason.contains(kata_types::workflow::SHELL_CAPTURE_TRUNCATED_MARKER),
        "{reason}"
    );
    let accepted: i64 = raw(&unstopped.op_path)
        .query_row(
            "SELECT count(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted, 0, "nothing was accepted");
    drop(unstopped.dir);

    let rig = rig();
    let frame = dispatched_capsule_attempt(&rig).await;
    rig.db
        .record_stop_request(
            frame.attempt_id,
            frame.lease_epoch,
            frame.placed_on.as_str(),
            "operator stop",
        )
        .expect("the durable ask, as `WorkflowExecutor::cancel` writes it");
    let mut truncated_completion = completed_capsule(&rig, &frame, empty_tree_result());
    if let kata_transport::types::WorkerMessage::CompletedCapsule {
        capture_exceeded, ..
    } = &mut truncated_completion
    {
        *capture_exceeded = true;
    }
    reactor(&rig)
        .handle_message_for_test(truncated_completion)
        .expect("a judged capture is the attempt's outcome");
    let (state, reason) = last_transition(&rig, frame.attempt_id);
    assert_eq!(state, "cancelled", "{reason}");
    assert!(
        reason.contains(kata_types::workflow::SHELL_CAPTURE_TRUNCATED_MARKER),
        "{reason}"
    );
    drop(rig.dir);
}

// ---------------------------------------------------------------------------
// Contract v7's authored capsule budgets — the authoring doors
// ---------------------------------------------------------------------------

/// **`output_bytes=`/`work_delta_bytes=`/`work_delta_entries=` lower into the
/// checked stage — and into its `contract_hash` — under `oci`.**
///
/// The pack-authoring claim: an authored capture bound is a
/// DIFFERENT stage, hashed so, and an unauthored one carries no field (the
/// `skip_serializing_if` gate keeps the JSON `policies` object of a kwarg-less
/// pack free of all three keys).
#[test]
fn the_capture_budget_kwargs_lower_and_hash_under_oci() {
    kata_types::node_profile::mark_node_installed();
    let pack = |suffix: &str| {
        format!(
            "cap = stage(id = \"cap\", agent = \"shell\", run = \"true\"{suffix})\n\
             workflow(\"cap-pack\", root = [cap])\n"
        )
    };
    let authored = compile_starlark_execution_program(
        &pack(", output_bytes = 1048576, work_delta_bytes = 2097152, work_delta_entries = 64"),
        "cap.star",
        &[],
    )
    .expect("the v7 kwargs compile under oci");
    let stage = authored.stages.values().next().expect("the one stage");
    assert_eq!(stage.policies.output_bytes, Some(1_048_576));
    assert_eq!(stage.policies.work_delta_bytes, Some(2_097_152));
    assert_eq!(stage.policies.work_delta_entries, Some(64));

    let plain = compile_starlark_execution_program(&pack(""), "cap.star", &[])
        .expect("the same pack without the kwargs compiles");
    let plain_stage = plain.stages.values().next().expect("the one stage");
    assert_eq!(
        plain_stage.policies.output_bytes, None,
        "unauthored stays absent"
    );
    assert_ne!(
        plain_stage.contract_hash, stage.contract_hash,
        "an authored bound is a different stage — the kwarg folds the contract hash"
    );
    // Byte-identity of the omission: serialize the authored-vs-plain stage and
    // the plain one's policies carry NONE of the three keys.
    let json = serde_json::to_value(&plain_stage.policies).expect("policies serialize");
    for key in ["output_bytes", "work_delta_bytes", "work_delta_entries"] {
        assert!(
            json.as_object().expect("an object").get(key).is_none(),
            "an unauthored {key} is not serialized — omitting the kwarg leaves the bytes unchanged"
        );
    }
    let authored_json = serde_json::to_value(&stage.policies).expect("authored policies serialize");
    assert_eq!(authored_json["output_bytes"], serde_json::json!(1_048_576));
}

/// **An authored `output_bytes` OVER the node's ceiling is refused at admission —
/// `capsule_budget_over_node_ceiling`, naming the stage, field, value and
/// ceiling.**
#[test]
fn an_authored_budget_over_the_node_ceiling_is_refused_at_admission() {
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            output_bytes: 1 << 20,
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    let refusal = compile_starlark_execution_program(
        "big = stage(id = \"big\", agent = \"shell\", run = \"yes\", output_bytes = 2097152)\n\
         workflow(\"big-pack\", root = [big])\n",
        "big.star",
        &[],
    )
    .expect_err("2 MiB authored on a node whose ceiling is 1 MiB")
    .to_string();
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
    assert!(
        refusal.contains("capsule_budget_over_node_ceiling"),
        "the named refusal: {refusal}"
    );
    for name in ["big", "output_bytes", "2097152", "1048576"] {
        assert!(
            refusal.contains(name),
            "the refusal must name {name} (stage/field/value/ceiling): {refusal}"
        );
    }

    // THE BOUNDARY — a budget authored AT the ceiling admits: the refused set
    // is strictly `value > ceiling`, so equality is a promise the node itself
    // declared reachable.
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            output_bytes: 1 << 20,
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    compile_starlark_execution_program(
        "at = stage(id = \"at\", agent = \"shell\", run = \"yes\", output_bytes = 1048576)\n\
         workflow(\"at-pack\", root = [at])\n",
        "at.star",
        &[],
    )
    .expect("1 MiB authored on a node whose ceiling is 1 MiB admits");
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
}

/// **A capsule stage whose RECORDED bound exceeds a bound it would be
/// recorded under is refused at admission.** `capsule_assembly` writes the
/// authored-or-default value for memory and the default for `pids.max`; the
/// refusal is `capsule_budget_over_node_ceiling` for an authored `memory_mb`
/// or the assembly default over the node's DECLARED ceiling. The ceilings are
/// `Option` — absent declares no ceiling, so a 4 GiB authored shell stage
/// admits; a shipped ceiling would have refused an ordinary build stage.
#[test]
fn a_capsule_stage_whose_recorded_bound_exceeds_a_ceiling_is_refused_at_admission() {
    kata_types::node_profile::mark_node_installed();
    // The installed ceilings are a process global — start from the shipped
    // default (no declared ceilings) rather than inherit a sibling's.
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
    // NO DECLARED CEILING — the shipped default (`None`): a node declares no
    // capsule ceiling until the operator says otherwise, so even a 4 GiB
    // authored shell stage admits — a shipped ceiling would have refused an
    // ordinary build stage.
    let shell_pack = |id: &str, memory_mb: u32| {
        format!(
            "{id} = stage(id = \"{id}\", agent = \"shell\", run = \"true\", \
             sandbox = sandbox_profile(image = {{\"memory_mb\": {memory_mb}}}))\n\
             workflow(\"{id}-pack\", root = [{id}])\n"
        )
    };
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
    compile_starlark_execution_program(&shell_pack("big", 4096), "big.star", &[])
        .expect("a 4 GiB authored shell stage admits with no declared ceiling");

    // A DECLARED 1 GiB memory ceiling: an authored value over it is refused
    // `capsule_budget_over_node_ceiling`.
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            capsule_memory_bytes: Some(1 << 30),
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    let refusal = compile_starlark_execution_program(&shell_pack("fat", 2048), "fat.star", &[])
        .expect_err("a 2 GiB authored shell stage over the declared 1 GiB ceiling")
        .to_string();
    assert!(
        refusal.contains("capsule_budget_over_node_ceiling"),
        "the authored-bound refusal is BY NAME: {refusal}"
    );
    for name in [
        "fat",
        "memory_mb",
        "2147483648",
        "1073741824",
        "capsule_memory_bytes_ceiling",
    ] {
        assert!(
            refusal.contains(name),
            "the authored-bound refusal must name {name}: {refusal}"
        );
    }
    compile_starlark_execution_program(&shell_pack("slim", 512), "slim.star", &[])
        .expect("a 512 MiB authored shell stage admits under the declared 1 GiB ceiling");

    // THE BOUNDARIES — every refused set is strictly `>`, so each bound AT its
    // comparison admits. The recorded DEFAULTS at their ceilings: a shell stage authors no
    // process bound and may author no memory bound, so the capsule records
    // the assembly defaults — equal to the ceiling, both admit.
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            capsule_memory_bytes: Some(512 << 20),
            capsule_process_count: Some(64),
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    compile_starlark_execution_program(&shell_pack("edge", 512), "edge.star", &[])
        .expect("an authored 512 MiB equal to the memory ceiling admits");
    compile_starlark_execution_program(
        "plain = stage(id = \"plain\", agent = \"shell\", run = \"true\")\n\
         workflow(\"plain-pack\", root = [plain])\n",
        "plain.star",
        &[],
    )
    .expect("a stage authoring no bounds records the defaults, equal to the ceilings");
    // And the refused set is nonempty on the same arm: the recorded 64-process
    // default STRICTLY over a 32 ceiling refuses.
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            capsule_process_count: Some(32),
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    let refusal = compile_starlark_execution_program(&shell_pack("procs", 512), "procs.star", &[])
        .expect_err("the recorded 64-process default over a 32 ceiling")
        .to_string();
    assert!(
        refusal.contains("capsule_budget_over_node_ceiling"),
        "the recorded-default refusal is BY NAME: {refusal}"
    );

    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
}

/// **A `workspace_effect` stage is not a capsule, so the recorded-bounds door
/// does not charge it.** The door runs for `subworkflow.is_none() &&
/// !stage_routes_to_workspace_effect(stage)` — under a ceiling below the
/// capsule defaults an effect stage still admits, because no box is recorded
/// for a stage that runs no process.
#[test]
fn a_workspace_effect_stage_is_not_charged_the_capsule_bounds() {
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            capsule_process_count: Some(32),
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    compile_starlark_execution_program(
        "ship = stage(id = \"ship\", agent = \"workspace_effect\", op = \"park\")\n\
         workflow(\"effect-pack\", root = [ship], worktree_isolated = True)\n",
        "effect-pack.star",
        &[],
    )
    .expect("a workspace_effect stage carries no recorded bounds to charge");
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
}

// ---------------------------------------------------------------------------
// The ISOLATED `/work` producer arm
// ---------------------------------------------------------------------------

/// The shipped pack compiled with `worktree_isolated = True` — the one workflow
/// kwarg the producer split keys on (`execution_program.summary.worktree_isolated`).
fn isolated_program() -> kata_program::execution_program::ExecutionProgram {
    let patched = SHIPPED_PACK.replace(
        "    root = [probe],",
        "    root = [probe],\n    worktree_isolated = True,",
    );
    assert_ne!(
        patched, SHIPPED_PACK,
        "the worktree_isolated patch must apply"
    );
    compile_starlark_execution_program(&patched, "sandbox-smoke-shell-offline.star", &[])
        .expect("the shipped pack compiled isolated")
}

/// A runner over `isolated_program` on `rig`'s planes — the same shape
/// [`runner`] builds, with the program's own admission door run first.
fn isolated_runner(rig: &Rig) -> WorkflowRunner {
    let program = isolated_program();
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program_with_target(
            rig.execution_id,
            &program,
            kata_types::test_support::fixture_trunk_target(),
        )
        .expect("the program is retained");
    WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
        .expect("the runner builds")
        .with_cache_store(Arc::clone(&rig.store))
}

/// The admission-side producer: convert a one-member committed base tree and
/// record the execution's `/work` head, through the same function
/// `kata_api`'s admission calls.
fn record_head(rig: &Rig, member: &[u8]) -> kata_core::operational::ExecutionWorkTreeHead {
    kata_core::work_tree::publish_base_tree_head(&rig.db, &rig.cas, rig.execution_id, |put| {
        let object = put(member)?;
        let manifest = kata_types::tree_artifact::TreeManifest::new(vec![
            kata_types::tree_artifact::TreeEntry {
                path: kata_types::tree_artifact::TreePath::new("base.txt").unwrap(),
                node: kata_types::tree_artifact::TreeNode::File {
                    mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                    object,
                    size_bytes: member.len() as u64,
                },
            },
        ])
        .unwrap();
        let manifest_bytes = manifest.manifest_bytes().unwrap();
        Ok(kata_types::tree_artifact::CommittedBaseTree {
            base_commit: "d1isolatedbase".to_owned(),
            manifest,
            manifest_bytes,
            candidate_commit_id: "d1isolatedwc".to_owned(),
        })
    })
    .expect("the committed base publishes")
}

/// An isolated execution whose admission never recorded a `/work` head refuses
/// at the producer split, BY NAME, before any walk could substitute — the
/// crash-window state `after_base_tree_published_before_head_recorded` leaves
/// is exactly this rig's.
#[tokio::test]
async fn an_isolated_execution_without_a_recorded_work_head_is_refused_by_name() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = isolated_runner(&rig);
    let directive = directive(&rig).await;

    let error = runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo isolated"),
        )
        .await
        .expect_err("an isolated execution with no /work head has no input to map");
    assert!(
        error.to_string().contains("work_tree_head_unrecorded"),
        "the refusal is named: {error}"
    );
    // And nothing reached the durable surface: no occurrence, no capsule, no
    // per-attempt walked tree artifact — the refusal precedes all of it.
    let (occurrences, capsules, trees): (i64, i64, i64) = raw(&rig.op_path)
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences),
                    (SELECT count(*) FROM capsules),
                    (SELECT count(*) FROM artifacts WHERE kind = 'tree')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((occurrences, capsules, trees), (0, 0, 0));
}

/// The isolated arm end to end on the host-free rig: the capsule authorizes
/// over the RECORDED head, the frame crosses the transport, and the durable
/// rows prove the producer split — exactly ONE execution tree artifact (the
/// admission's committed base) where the walked arm would mint a second, and
/// the occurrence bound to the head's artifact.
#[tokio::test]
async fn an_isolated_execution_maps_its_recorded_base_head_at_work() {
    let rig = rig();
    declare_promoted_environment(&rig);
    let runner = isolated_runner(&rig);
    let head = record_head(&rig, b"the committed base, not the scratch dir\n");
    let directive = directive(&rig).await;

    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(SHIPPED_STAGE),
            directive,
            &RenderedCommand::rendered("echo isolated"),
        )
        .await
        .expect("an isolated execution with a recorded head authorizes");

    let _frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it");

    // TWO `kind='tree'` artifacts exist — the admission's committed base and
    // the canonical empty tree `/out` and `/tmp` map — and NO third: the
    // isolated arm never mints a per-attempt walk receipt.
    let (trees, bound): (i64, Vec<u8>) = raw(&rig.op_path)
        .query_row(
            "SELECT (SELECT count(*) FROM artifacts WHERE kind = 'tree'),
                    (SELECT work_tree_artifact_id FROM occurrences)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        trees, 2,
        "the head tree plus the empty tree — no per-attempt walk artifact"
    );
    assert_eq!(
        bound,
        head.work_tree_artifact_id.to_vec(),
        "the occurrence binds the execution's recorded head"
    );
}

/// **The recorded git view reaches the submitted capsule.** An isolated `oci`
/// execution whose program contains an agent stage
/// records an `execution_git_views` row at admission, and the capsule the
/// worker receives carries THAT row — history artifact ref, base commit and
/// branch, the scratch identity — on its `git_view` field. The assertion
/// reads the capsule's own published bytes, so a dispatch that attached
/// `None` (or any row but the recorded one) fails here.
#[tokio::test]
async fn the_recorded_git_view_reaches_an_isolated_agent_capsule() {
    kata_types::node_profile::mark_node_installed();
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some("nanocode_openai".to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "subscription".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        },
    );
    kata_types::node_profile::install_node_agents(agents);

    let rig = rig();
    declare_promoted_environment(&rig);
    let program = compile_starlark_execution_program(
        "verdict = stage(\n\
         \x20   id = \"verdict\",\n\
         \x20   agent = \"codex\",\n\
         \x20   prompt = \"review the diff\",\n\
         \x20   sandbox = sandbox_profile(),\n\
         )\n\
         workflow(\"agent-isolated\", root = [verdict], worktree_isolated = True)\n",
        "agent-isolated.star",
        &[],
    )
    .expect("the isolated agent pack compiles");
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program_with_target(
            rig.execution_id,
            &program,
            kata_types::test_support::fixture_trunk_target(),
        )
        .expect("the program is retained");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("verdict")))
        .expect("the agent stage is present");
    let directive = rig
        .dispatcher
        .resolve_sandbox(
            stage.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            rig.execution_id,
            stage.should_confine_to_declared_inputs(),
            stage.is_content_cacheable(),
        )
        .await
        .expect("the agent profile resolves");
    let runner =
        WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
            .expect("the runner builds")
            .with_cache_store(Arc::clone(&rig.store));
    let head = record_head(&rig, b"the committed base the view is rooted at\n");

    // Admission's half: the view artifact published and the row recorded,
    // through the same `kata_core` function the api admission calls.
    let view = kata_core::git_view::publish_execution_git_view(
        &rig.db,
        &rig.cas,
        rig.execution_id,
        |put| {
            let member_bytes: &[u8] = b"pack member bytes the history artifact carries\n";
            let member = put(member_bytes)?;
            let manifest = kata_types::tree_artifact::TreeManifest::new(vec![
                kata_types::tree_artifact::TreeEntry {
                    path: kata_types::tree_artifact::TreePath::new(
                        "objects/pack/pack-deadbeef.pack",
                    )
                    .unwrap(),
                    node: kata_types::tree_artifact::TreeNode::File {
                        mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                        object: member,
                        size_bytes: member_bytes.len() as u64,
                    },
                },
            ])
            .unwrap();
            let manifest_bytes = manifest.manifest_bytes().unwrap();
            Ok(kata_types::tree_artifact::CommittedBaseGitView {
                base_commit: "d1gitviewbase".to_owned(),
                branch: Some(kata_types::execution_contract::GitViewRef {
                    name: "trunk".into(),
                    commit: "d1gitviewbase".into(),
                }),
                identity: kata_types::execution_contract::GitIdentity {
                    name: "kata tests".into(),
                    email: "kata-tests@localhost".into(),
                },
                manifest,
                manifest_bytes,
            })
        },
    )
    .expect("the execution's git view publishes and records");

    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new("verdict"),
            directive,
            &RenderedCommand::rendered("review the diff"),
        )
        .await
        .expect("an isolated agent stage with a recorded head authorizes");

    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it");
    let DispatchFrame::Capsule(capsule) = &frame;
    let bytes = rig
        .cas
        .get(&capsule.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let body: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    let git_view = body
        .git_view()
        .expect("the isolated agent capsule carries the recorded git view");
    let declared_object: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
            [view.history_artifact_id.as_slice()],
            |row| row.get(0),
        )
        .expect("the recorded view's artifact row resolves");
    assert_eq!(
        git_view.history.object_id().0.to_vec(),
        declared_object,
        "the capsule's history ref is the recorded row's artifact"
    );
    assert_eq!(git_view.base_commit.as_str(), "d1gitviewbase");
    assert_eq!(
        git_view.branch.as_ref().map(|branch| branch.name.as_str()),
        Some("trunk")
    );
    assert_eq!(git_view.identity.name.as_str(), "kata tests");
    assert_eq!(git_view.identity.email.as_str(), "kata-tests@localhost");
    assert!(
        matches!(
            body.process(),
            kata_types::execution_contract::CapsuleProcess::Agent(_)
        ),
        "the capsule's process arm is the Agent turn the view is lawful on"
    );
    let _ = head;
}

/// A SHELL stage whose profile `requires` `git`, on a
/// worktree-isolated execution, carries the execution's recorded git view on
/// its `Command` capsule (`carries_git_view`) — the same row an agent capsule
/// carries — read off the capsule's own published bytes.
///
/// **Would red if:** the submit still gated the view on the agent class
/// (`git_view` would be `None`), or `Capsule::new` still refused a view on a
/// `Command` process.
#[tokio::test]
async fn a_shell_stage_requiring_git_carries_the_recorded_git_view() {
    kata_types::node_profile::mark_node_installed();
    let rig = rig();
    declare_promoted_environment(&rig);
    let program = compile_starlark_execution_program(
        "verdict = stage(\n\
         \x20   id = \"verdict\",\n\
         \x20   agent = \"shell\",\n\
         \x20   run = \"git status --short\",\n\
         \x20   sandbox = sandbox_profile(workspace = \"ro\", requires = [\"git\"]),\n\
         )\n\
         workflow(\"shell-git-isolated\", root = [verdict], worktree_isolated = True)\n",
        "shell-git-isolated.star",
        &[],
    )
    .expect("the isolated shell-git pack compiles");
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program_with_target(
            rig.execution_id,
            &program,
            kata_types::test_support::fixture_trunk_target(),
        )
        .expect("the program is retained");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("verdict")))
        .expect("the shell stage is present");
    let directive = rig
        .dispatcher
        .resolve_sandbox(
            stage.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            rig.execution_id,
            stage.should_confine_to_declared_inputs(),
            stage.is_content_cacheable(),
        )
        .await
        .expect("the shell profile resolves");
    let runner =
        WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
            .expect("the runner builds")
            .with_cache_store(Arc::clone(&rig.store));
    let head = record_head(&rig, b"the committed base the view is rooted at\n");

    // Admission's half: the view artifact published and the row recorded,
    // through the same `kata_core` function the api admission calls.
    let view = kata_core::git_view::publish_execution_git_view(
        &rig.db,
        &rig.cas,
        rig.execution_id,
        |put| {
            let member_bytes: &[u8] = b"pack member bytes the history artifact carries\n";
            let member = put(member_bytes)?;
            let manifest = kata_types::tree_artifact::TreeManifest::new(vec![
                kata_types::tree_artifact::TreeEntry {
                    path: kata_types::tree_artifact::TreePath::new(
                        "objects/pack/pack-deadbeef.pack",
                    )
                    .unwrap(),
                    node: kata_types::tree_artifact::TreeNode::File {
                        mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                        object: member,
                        size_bytes: member_bytes.len() as u64,
                    },
                },
            ])
            .unwrap();
            let manifest_bytes = manifest.manifest_bytes().unwrap();
            Ok(kata_types::tree_artifact::CommittedBaseGitView {
                base_commit: "d1gitviewbase".to_owned(),
                branch: Some(kata_types::execution_contract::GitViewRef {
                    name: "trunk".into(),
                    commit: "d1gitviewbase".into(),
                }),
                identity: kata_types::execution_contract::GitIdentity {
                    name: "kata tests".into(),
                    email: "kata-tests@localhost".into(),
                },
                manifest,
                manifest_bytes,
            })
        },
    )
    .expect("the execution's git view publishes and records");

    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new("verdict"),
            directive,
            &RenderedCommand::rendered("git status --short"),
        )
        .await
        .expect("an isolated shell stage requiring git authorizes");

    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a frame reaches the worker")
    .expect("the transport delivers it");
    let DispatchFrame::Capsule(capsule) = &frame;
    let bytes = rig
        .cas
        .get(&capsule.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let body: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    let git_view = body
        .git_view()
        .expect("the shell capsule requiring git carries the recorded git view");
    let declared_object: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
            [view.history_artifact_id.as_slice()],
            |row| row.get(0),
        )
        .expect("the recorded view's artifact row resolves");
    assert_eq!(
        git_view.history.object_id().0.to_vec(),
        declared_object,
        "the capsule's history ref is the recorded row's artifact"
    );
    assert_eq!(git_view.base_commit.as_str(), "d1gitviewbase");
    assert_eq!(
        git_view.branch.as_ref().map(|branch| branch.name.as_str()),
        Some("trunk")
    );
    assert_eq!(git_view.identity.name.as_str(), "kata tests");
    assert_eq!(git_view.identity.email.as_str(), "kata-tests@localhost");
    assert!(
        matches!(
            body.process(),
            kata_types::execution_contract::CapsuleProcess::Command { .. }
        ),
        "the view rides a COMMAND capsule — a shell stage requiring git"
    );
    let _ = head;
}

/// A stage whose profile `requires` a program the bound
/// environment does not provide on its `PATH` is refused BEFORE anything is
/// claimed or delivered (`capsule_requirement_not_in_environment`, naming the
/// program), even when CHECK could not judge it (this process bound no
/// environment programs). Raw: no attempt row, no frame.
#[tokio::test]
async fn a_requirement_the_environment_lacks_is_refused_before_dispatch() {
    kata_types::node_profile::mark_node_installed();
    let rig = rig();
    declare_promoted_environment(&rig);
    let program = compile_starlark_execution_program(
        "build = stage(\n\
         \x20   id = \"build\",\n\
         \x20   agent = \"shell\",\n\
         \x20   run = \"cargo build\",\n\
         \x20   sandbox = sandbox_profile(workspace = \"ro\", requires = [\"cargo\", \"git\"]),\n\
         )\n\
         workflow(\"needs-cargo\", root = [build])\n",
        "needs-cargo.star",
        &[],
    )
    .expect("CHECK cannot judge `requires` without bound environment programs");
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program(rig.execution_id, &program)
        .expect("the program is retained");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("build")))
        .expect("the stage is present");
    let directive = rig
        .dispatcher
        .resolve_sandbox(
            stage.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            rig.execution_id,
            stage.should_confine_to_declared_inputs(),
            stage.is_content_cacheable(),
        )
        .await
        .expect("the profile resolves");
    let runner =
        WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), rig.execution_id)
            .expect("the runner builds")
            .with_cache_store(Arc::clone(&rig.store));
    let _head = record_head(&rig, b"the base\n");
    let refusal = runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new("build"),
            directive,
            &RenderedCommand::rendered("cargo build"),
        )
        .await
        .expect_err("a missing required program refuses the dispatch")
        .to_string();
    assert!(
        refusal.contains("capsule_requirement_not_in_environment")
            && refusal.contains("\"cargo\"")
            && !refusal.contains("\"git\""),
        "refused by name, naming exactly the missing program: {refusal}"
    );
    let attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1",
            [rig.execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt count reads");
    assert_eq!(attempts, 0, "nothing was claimed");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            rig.worker_side.recv_frame()
        )
        .await
        .is_err(),
        "no frame reached the worker"
    );
}

/// THE CREDENTIAL REFUSAL — an `[agents.<label>] credential` the contract
/// cannot read is `credential_undeclared` at CHECK, named like the adapter
/// arms.
#[test]
fn a_bad_credential_spelling_is_refused_at_check_under_the_oci_profile() {
    kata_types::node_profile::mark_node_installed();
    for (case, mode, source) in [
        ("a mode the contract cannot read", "oauth", "kata_login"),
        (
            "a source the contract cannot read",
            "subscription",
            "my_home_dir",
        ),
        (
            "a subscription declared against env:",
            "subscription",
            "env:KEY",
        ),
        (
            "another tool's login, which is no source",
            "api_key",
            "codex_login",
        ),
    ] {
        let mut agents = std::collections::BTreeMap::new();
        agents.insert(
            "codex".to_owned(),
            kata_types::config::AgentBackendConfig::Harness {
                model: None,
                reasoning_effort: None,
                adapter: Some("nanocode_openai".to_owned()),
                credential: Some(kata_types::config::AgentCredentialDecl {
                    mode: mode.to_owned(),
                    source: source.to_owned(),
                }),
                env: std::collections::BTreeMap::new(),
            },
        );
        kata_types::node_profile::install_node_agents(agents);
        let refusal = compile_starlark_execution_program(
            "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review it\")\n\
             workflow(\"agent-pack\", root = [verdict])\n",
            "agent-pack.star",
            &[],
        )
        .expect_err("the case is refused at CHECK")
        .to_string();
        assert!(
            refusal.contains("credential_undeclared"),
            "{case}: the refusal is BY NAME: {refusal}"
        );
    }
}

/// **THE SHELL `net = "host"` DOOR AT CHECK.** A shell stage's authored
/// `net = "host"` names exactly the node's `[node] egress_allow` set — so a
/// node that declares NO authority refuses the stage `egress_undeclared` BY
/// NAME (an empty set is `egress_undeclared`, not `Offline`: `net =
/// "offline"` is the authored spelling for no egress). The refused set is
/// exactly the authoring stage — a `net = "offline"` sibling beside it is
/// admitted. A node WITH authorities admits the stage.
///
/// **Would red if:** the door read `NetPolicy::Offline` instead of `Host`
/// (the refusal would still fire, on the wrong stage), or dropped the
/// `is_shell_class` guard (an agent stage — judged by its own egress door,
/// `egress_undeclared` — would be refused by a door that does not name its
/// own set).
#[test]
fn a_host_net_shell_stage_names_the_nodes_egress_allow_at_check() {
    const PACK: &str = "probe = stage(id = \"probe\", agent = \"shell\", run = \"getent \
         hosts api.example.com\", sandbox = \"s\", timeout_ms = 30000)\n\
         quiet = stage(id = \"quiet\", agent = \"shell\", run = \"true\", sandbox = \"o\", \
         timeout_ms = 30000)\n\
         workflow(\"egress-pack\", root = [probe, quiet], sandbox_profiles = \
         {\"s\": sandbox_profile(workspace = \"scratch\", net = \"host\"), \
         \"o\": sandbox_profile(workspace = \"scratch\", net = \"offline\")})\n";
    // A node declaring NO egress_allow authority refuses the authoring stage
    // by name — and ONLY that stage.
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
    kata_types::node_profile::mark_node_installed();
    let refusal = compile_starlark_execution_program(PACK, "egress-pack.star", &[])
        .expect_err("host egress with no declared authority is refused")
        .to_string();
    assert!(
        refusal.contains("egress_undeclared") && refusal.contains("\"probe\""),
        "the refusal names the stage and the door: {refusal}"
    );
    assert!(
        !refusal.contains("\"quiet\""),
        "an offline sibling is outside the refused set: {refusal}"
    );

    // A node WITH an authority admits the same pack.
    let mut allow = std::collections::BTreeSet::new();
    allow.insert(
        kata_types::execution_contract::EgressAuthority::from_authority_str("api.example.com:443")
            .expect("a host:port authority parses"),
    );
    kata_types::node_profile::install_node_egress_allow(allow);
    compile_starlark_execution_program(PACK, "egress-pack.star", &[])
        .expect("the declared authority admits the stage");
}

/// **THE AGENT SIDE of `egress_undeclared`.** An agent stage's authored `net =
/// "host"` names the node's `[node] egress_allow` — its model calls leave from
/// the process hosting the worker, so its credential opens no endpoint of the
/// capsule's — and under `oci` a stage on a node that declares none is refused
/// `egress_undeclared` BY NAME, naming the stage. The refused set is exactly
/// the empty set under an authored `host`: a declared authority admits the
/// same stage, and a stage authored `net = "offline"`, or authoring no
/// `sandbox=` at all (its materialized default is `offline`), is outside the
/// door's question entirely.
///
/// **Would red if:** the door were removed (the pack compiles on a node that
/// declares nothing), or a credential were counted as a fill again.
#[test]
fn an_agent_stages_host_net_is_refused_only_when_the_nodes_egress_allow_is_empty() {
    const PACK: &str = "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \
         \"review it\", sandbox = \"h\")\nworkflow(\"p\", root = [verdict], \
         sandbox_profiles = {\"h\": sandbox_profile(net = \"host\")})\n";
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
        "codex".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    )]));
    let allow = |entries: &[&str]| {
        kata_types::node_profile::install_node_egress_allow(
            entries
                .iter()
                .map(|entry| {
                    kata_types::execution_contract::EgressAuthority::from_authority_str(entry)
                        .expect("an authority parses")
                })
                .collect(),
        );
    };

    // THE REFUSED SET: a credentialed agent, and no `[node] egress_allow`.
    allow(&[]);
    let refusal = compile_starlark_execution_program(PACK, "p.star", &[])
        .expect_err("an agent stage's host net over an empty set is refused")
        .to_string();
    assert!(
        refusal.contains("egress_undeclared") && refusal.contains("\"verdict\""),
        "the refusal names the door and the stage: {refusal}"
    );
    assert!(
        refusal.contains("[node] egress_allow"),
        "the refusal names the set that could have filled it: {refusal}"
    );

    // A declared authority admits the stage.
    allow(&["node.example.com:443"]);
    compile_starlark_execution_program(PACK, "p.star", &[])
        .expect("`[node] egress_allow` fills the set");

    // And the authored `net = "offline"` stage is outside the refused set —
    // the door asks the `host` posture's question, and `offline` is the
    // spelling that does not ask it.
    allow(&[]);
    const OFFLINE: &str = "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \
         \"review it\", sandbox = \"o\")\nworkflow(\"p\", root = [verdict], \
         sandbox_profiles = {\"o\": sandbox_profile(workspace = \"scratch\", \
         net = \"offline\")})\n";
    compile_starlark_execution_program(OFFLINE, "p.star", &[])
        .expect("`net = \"offline\"` authors nothing to fill");
    const UNAUTHORED: &str = "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \
         \"review it\")\nworkflow(\"p\", root = [verdict])\n";
    compile_starlark_execution_program(UNAUTHORED, "p.star", &[])
        .expect("an unauthored model stage materializes `net = \"offline\"`: nothing to fill");
}

/// **THE `sandbox = "host"` DOOR AT CHECK.** Under `oci` a stage's containment
/// IS the capsule, so a stage that opts out of containment has no capsule
/// form: an inline `sandbox = "host"` refuses `host_sandbox_unsupported_under_oci`
/// BY NAME, and a sandbox NAME that resolves to nothing is the conservative
/// same — refused rather than defaulted to a confinement the author did not
/// declare. The refused set is exactly the opting-out stage: a `memory_snapshot()`
/// sibling (no process at all) and a confined shell stage admit.
///
/// **Would red if:** the door checked `exec != Host` (every confined stage
/// would refuse), or the exemption dropped `memory_snapshot` (the builtin's
/// inert placeholder would refuse the one stage that never runs a process).
#[test]
fn the_host_sandbox_door_refuses_the_opt_out_and_only_the_opt_out() {
    kata_types::node_profile::mark_node_installed();
    // Inline opt-out — refused by name, naming the stage. A `memory_snapshot()`
    // sibling and a confined stage sit beside it: the first runs no process at
    // all and the second declares a scratch profile, so the refusal must name
    // `hot` alone.
    const INLINE: &str = "hot = stage(id = \"hot\", agent = \"shell\", run = \"id\", \
         sandbox = \"host\")\nconfined = stage(id = \"confined\", agent = \"shell\", \
         run = \"true\", sandbox = \"s\")\nsnap = memory_snapshot(id = \"snap\")\n\
         workflow(\"p\", root = [confined, hot, snap], \
         sandbox_profiles = {\"s\": sandbox_profile(workspace = \"scratch\", \
         net = \"offline\")})\n";
    let refusal = compile_starlark_execution_program(INLINE, "inline.star", &[])
        .expect_err("the host opt-out has no capsule form")
        .to_string();
    assert!(
        refusal.contains("host_sandbox_unsupported_under_oci") && refusal.contains("\"hot\""),
        "the refusal names the opting stage: {refusal}"
    );
    for sibling in ["\"confined\"", "\"snap\""] {
        assert!(
            !refusal.contains(sibling),
            "{sibling} is outside the refused set: {refusal}"
        );
    }
    // An unresolved sandbox NAME reads as host-unconfined under the same
    // door. The loader refuses an authored dangling name itself, so the
    // conservative reading is exercised the way it can actually occur — a
    // program read back whose `sandbox_profiles` map no longer carries the
    // name.
    kata_types::node_profile::mark_node_installed();
    let mut program = compile_starlark_execution_program(
        "ghost = stage(id = \"ghost\", agent = \"shell\", run = \"id\", \
         sandbox = \"defined\")\nworkflow(\"p\", root = [ghost], sandbox_profiles = \
         {\"defined\": sandbox_profile(workspace = \"rw\", net = \"offline\")})\n",
        "named.star",
        &[],
    )
    .expect("the named profile compiles on oci");
    program.sandbox_profiles.clear();
    let refusal = kata_program::execution_program::refuse_program_at_check_or_recovery(
        &program,
        &mut std::collections::BTreeSet::new(),
    )
    .expect_err("an unresolved name is host-unconfined by the conservative reading")
    .to_string();
    assert!(
        refusal.contains("host_sandbox_unsupported_under_oci") && refusal.contains("\"ghost\""),
        "the unresolved name is refused, not defaulted: {refusal}"
    );
}

/// A topology stage — static role list or DYNAMIC fanout —
/// takes capsule form: its members are capsules of the stage's own posture,
/// so every per-stage posture door judges it like a plain stage. A
/// `sandbox = "host"` opt-out is refused `host_sandbox_unsupported_under_oci`;
/// a model stage over an undeclared `[agents.*]` label is refused by the agent
/// declaration door — on both spellings, and never `child_invocation`.
///
/// **Would red if:** a dynamic fanout still had no capsule form (it would be
/// refused structurally, before any posture door).
#[test]
fn a_topology_static_or_dynamic_is_judged_by_its_posture() {
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::new());
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
    for dynamic in ["", ", dynamic_fanout = True"] {
        let host = format!(
            "fan = stage(id = \"fan\", agent = \"shell\", run = \"true\", \
             sandbox = \"host\", topology = topology(\"t\", workers = \
             [role(\"w\", agent = \"shell\")]{dynamic}))\n\
             workflow(\"p\", root = [fan])\n"
        );
        let refusal = compile_starlark_execution_program(&host, "p.star", &[])
            .expect_err("a topology's host opt-out is refused")
            .to_string();
        assert!(
            refusal.contains("host_sandbox_unsupported_under_oci")
                && !refusal.contains("child_invocation"),
            "{dynamic:?}: judged by its posture: {refusal}"
        );
        let model = format!(
            "fan = stage(id = \"fan\", agent = \"codex\", prompt = \"plan\", \
             topology = topology(\"t\", workers = \
             [role(\"w\", agent = \"codex\")]{dynamic}))\n\
             workflow(\"p\", root = [fan])\n"
        );
        let refusal = compile_starlark_execution_program(&model, "p.star", &[])
            .expect_err("an undeclared agent label is refused")
            .to_string();
        assert!(
            refusal.contains("adapter_undeclared") && !refusal.contains("child_invocation"),
            "{dynamic:?}: judged by the agent declaration door: {refusal}"
        );
    }
}

/// EVERY shipped pack that once authored `sandbox = "host"` now declares the
/// confined profile its stages need, and each CHECKS under `oci`, audited
/// against the `[agents.*]` adapters (`nanocode_openai` under kata's own
/// ChatGPT login) and `[node] egress_allow` a real deployment declares: no host
/// door, no dollar bound its credential cannot price (a std pack authors a
/// `time_bound` alone), and none of `child_invocation`, `egress_undeclared` or
/// the `agents.*` declaration doors.
#[test]
fn shipped_once_host_sandbox_packs_check_under_oci() {
    kata_types::node_profile::mark_node_installed();
    let backend = kata_program::test_harness::rig_agent_backend_config;
    // Every agent label the packs name — `shell`/`workspace_effect` are not
    // agent labels and need no declaration.
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([
        ("default".to_owned(), backend()),
        ("gate".to_owned(), backend()),
        ("reviewer".to_owned(), backend()),
    ]));
    let mut allow = std::collections::BTreeSet::new();
    allow.insert(
        kata_types::execution_contract::EgressAuthority::from_authority_str("api.example.com:443")
            .expect("an authority parses"),
    );
    kata_types::node_profile::install_node_egress_allow(allow);

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .join("workflows");
    let loader_roots = [
        root.join("std"),
        root.join("kata-factory"),
        root.join("examples"),
    ];
    let cases: &[&str] = &[
        // Each stage declares the confined workspace profile it needs.
        "examples/gate-fix-loop.star",
        "std/kata-work-item.star",
        "std/kata-gate-fix-loop.star",
        "smoke/std.software_factory.smoke.star",
        "smoke/std.software_factory.kata_self_improve_implementation_smoke.star",
        // The memory-context smoke's constructs, CHECK-admitted beside them.
        "smoke/memory-context-smoke.star",
        // No stage of the self-improve packs declares `sandbox = "host"`, so they
        // CHECK under `oci` beside the confined ones.
        "std/kata-loop-lite.star",
        "std/kata-loop-plan-check-std.star",
        "std/std.software_factory.kata_self_improve.star",
        "std/std.software_factory.kata_self_improve_preflight.star",
        // The in-loop factory packs author a `time_bound` alone (a std pack
        // authors no dollar limit), so the subscription-credentialed agents this
        // audit installs trip nothing, and they declare no host-bound stage.
        "std/std.software_factory.kata_self_improve_inloop.star",
        "std/std.software_factory.kata_self_improve_inloop_gatesplit.star",
    ];
    let mut outcomes = Vec::new();
    for rel in cases {
        let pack = root.join(rel);
        assert!(pack.is_file(), "{rel}: the shipped pack exists");
        let mut roots = loader_roots.to_vec();
        if let Some(dir) = pack.parent() {
            roots.insert(0, dir.to_path_buf());
        }
        if let Err(refusal) =
            kata_program::execution_program::compile_execution_program_from_file(&pack, &roots)
        {
            panic!(
                "{rel} was rewritten to a confined profile and must CHECK under `oci`, but \
                 refused: {refusal}"
            );
        }
        outcomes.push(format!("{rel}: CHECKED"));
    }
    eprintln!(
        "sandbox = \"host\" shipped-pack audit under `oci`:\n  {}",
        outcomes.join("\n  ")
    );
}

/// **`std/kata-gate-fix-loop.star` CHECKS with its two model labels (`default`,
/// `gate`) bound to every adapter under each credential mode it runs under**,
/// one source per row. The kinds are `AdapterKind::ALL`, and each kind's
/// credential modes come from one exhaustive match:
/// `nanocode_openai` under kata's ChatGPT login, kata's stored API key and an
/// `env:` key, and `nanocode_anthropic` under kata's stored API key and an
/// `env:` key (its `subscription` is refused by name,
/// `nanocode_anthropic_under_subscription_is_refused_credential_mode_unsupported_at_check`).
/// Its loop's only walk-away bound is a `time_bound`, which no adapter or
/// credential refuses; a loop `cost_bound` is refused on every row but the
/// `nanocode_anthropic` ones (`cost_bound_unenforceable_unpriced_adapter`).
///
/// **Would red if:** the pack's loop authored a `cost_bound` (the subscription
/// and `nanocode_openai` rows refuse), or a kind added without its rows here.
#[test]
fn the_gate_fix_loop_pack_checks_on_every_adapter_and_credential_mode() {
    use kata_types::agent::AdapterKind;
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str("api.example.com:443")
            .expect("an authority parses"),
    ]));
    type Credential = Option<(&'static str, &'static str)>;
    // No wildcard arm: a new kind does not compile until it is placed here.
    let rows_of = |kind: AdapterKind| -> Vec<Credential> {
        match kind {
            AdapterKind::NanocodeOpenai => vec![
                Some(("subscription", "kata_login")),
                Some(("api_key", "kata_login")),
                Some(("api_key", "env:OPENAI_API_KEY")),
            ],
            AdapterKind::NanocodeAnthropic => vec![
                Some(("api_key", "kata_login")),
                Some(("api_key", "env:ANTHROPIC_API_KEY")),
            ],
        }
    };
    let rows: Vec<(AdapterKind, Credential)> = AdapterKind::ALL
        .into_iter()
        .flat_map(|kind| {
            rows_of(kind)
                .into_iter()
                .map(move |credential| (kind, credential))
        })
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .join("workflows");
    let pack = root.join("std/kata-gate-fix-loop.star");
    let roots = [
        root.join("std"),
        root.join("kata-factory"),
        root.join("examples"),
    ];
    for (kind, credential) in rows {
        let adapter = kind.as_label();
        let backend = || kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some(adapter.to_owned()),
            credential: credential.map(|(mode, source)| kata_types::config::AgentCredentialDecl {
                mode: mode.to_owned(),
                source: source.to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        };
        kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([
            ("default".to_owned(), backend()),
            ("gate".to_owned(), backend()),
        ]));
        if let Err(refusal) =
            kata_program::execution_program::compile_execution_program_from_file(&pack, &roots)
        {
            panic!("{adapter} {credential:?}: the pack must CHECK, but refused: {refusal}");
        }
    }
}

/// **THE DECLARED-ENV DOOR AT CHECK.** A node's `[agents.<label>] env` key
/// naming a channel kata renders — the `HOME` the capsule's init renders —
/// is refused `capsule_agent_env_channel_owned` at admission, the same name
/// `Capsule::new` gives at dispatch, because the two doors share
/// `refuse_declared_agent_env`; the same config without the collision is
/// admitted.
///
/// **Would red if:** the CHECK arm dropped the `refuse_declared_agent_env`
/// call (the colliding row compiles), or the rendered set were a second list.
#[test]
fn a_declared_env_colliding_with_what_kata_renders_is_refused_at_check() {
    kata_types::node_profile::mark_node_installed();
    let install = |env: &[(&str, &str)]| {
        let mut agents = std::collections::BTreeMap::new();
        agents.insert(
            "codex".to_owned(),
            kata_types::config::AgentBackendConfig::Harness {
                model: None,
                reasoning_effort: None,
                adapter: Some("nanocode_openai".to_owned()),
                credential: Some(kata_types::config::AgentCredentialDecl {
                    mode: "subscription".to_owned(),
                    source: "kata_login".to_owned(),
                }),
                env: env
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
            },
        );
        kata_types::node_profile::install_node_agents(agents);
    };
    const PACK: &str = "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review it\")\n\
                        workflow(\"agent-pack\", root = [verdict])\n";

    // `HOME` is what the capsule's init renders — a node that declares it
    // would write beside kata's in the same `process.env` vector.
    install(&[("HOME", "/tmp/agent-home")]);
    let refusal = compile_starlark_execution_program(PACK, "agent-pack.star", &[])
        .expect_err("a declared env naming what kata renders refuses at CHECK")
        .to_string();
    assert!(
        refusal.contains("capsule_agent_env_channel_owned"),
        "the refusal is BY NAME: {refusal}"
    );
    assert!(
        refusal.contains("HOME") && refusal.contains("kata-toolhost"),
        "the refusal must name the variable and its channel: {refusal}"
    );

    // `XDG_RUNTIME_DIR` is kata's too: the worker keeps it for its
    // user-manager clients, so a node may not declare it either.
    install(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);
    let refusal = compile_starlark_execution_program(PACK, "agent-pack.star", &[])
        .expect_err("a declared XDG_RUNTIME_DIR refuses at CHECK")
        .to_string();
    assert!(
        refusal.contains("capsule_agent_env_channel_owned")
            && refusal.contains("XDG_RUNTIME_DIR")
            && refusal.contains("user-manager clients"),
        "the refusal names the variable and its owner: {refusal}"
    );

    // The same config with a non-colliding key is admitted.
    install(&[("TERM", "dumb")]);
    compile_starlark_execution_program(PACK, "agent-pack.star", &[])
        .expect("a declared env naming nothing kata renders is admitted");
}

/// A hard-dollar refusal's recourse: the arm's own `remedy`, and a `time_bound`
/// or a `token_bound` in place of the dollar bound — every kind's adapter
/// reports every token class, so a token ceiling can always be held.
fn recourse_is_invocable(refusal: &str, remedy: &str) {
    assert!(
        refusal.contains(remedy),
        "the refusal names its arm's remedy ({remedy}): {refusal}"
    );
    assert!(
        refusal.contains("`time_bound` or a `token_bound`"),
        "the refusal names the time bound and the token bound as the recourses: {refusal}"
    );
}

/// The adapter kinds a refusal offers in its `opener … )` list, read off its text.
fn named_kinds(refusal: &str, opener: &str) -> Vec<String> {
    refusal
        .split_once(opener)
        .and_then(|(_, rest)| rest.split_once(')'))
        .map_or_else(
            || panic!("the refusal lists kinds after {opener:?}: {refusal}"),
            |(list, _)| {
                list.split(", ")
                    .map(|label| label.trim_matches('`').to_owned())
                    .collect()
            },
        )
}

/// An agent block declaring `adapter`, a kind's own label, and `credential`.
fn launchable_agent(
    adapter: &str,
    credential: Option<kata_types::config::AgentCredentialDecl>,
) -> kata_types::config::AgentBackendConfig {
    assert!(
        kata_types::agent::AdapterKind::from_label(adapter).is_some(),
        "`{adapter}` names an adapter kind"
    );
    agent_block(adapter, credential)
}

/// A hard dollar bound over a stage whose spend kata cannot price is
/// refused AT CHECK, not halted on after the money moves, by the arm's NAME:
/// `cost_bound_unenforceable_unpriced_adapter` — an adapter with no
/// `billing_backend` (`nanocode_openai` at this rev, under its `env:` key and
/// under kata's own login alike): every turn meters `Unavailable` under EVERY
/// credential mode, so `api_key` is no remediation and the name must not blame
/// the credential. A different adapter is the fix.
///
/// `nanocode_anthropic` under `api_key` is priced (the Anthropic rows), so it
/// is admitted under the bound; under `subscription` it is refused
/// `credential_mode_unsupported` first, the mode door being judged before the
/// hard-dollar door — which is why no kind this build carries reaches the
/// door's subscription arm.
///
/// Each refusal names only recourses the operator can take — the arm's own
/// remediation, or a `time_bound` (or, for an adapter that reports every token
/// class, a `token_bound`) in place of the dollar bound.
///
/// What does NOT trip it is the point: a priced `api_key` turn under the same
/// bound is admitted (the bound is real), and the same unmeterable stage
/// under NO hard promise is admitted (nothing claimed, nothing to fail
/// closed on).
///
/// A `loop(bounds = [cost_bound(..)])` covers its body members and its gate exactly
/// as a workflow bound covers its stages — refused by the same two names, the loop
/// named as the bound's scope — and nothing outside the loop; a token or time
/// bound on the same loop, and a priced `api_key` member, are admitted.
///
/// **Would red if:** the door judged only a program's own (or an invoking
/// parent's) dollar bound — the loop rows compile — or a loop's body members
/// alone (the gate row compiles).
#[test]
fn a_hard_dollar_bound_over_unpriceable_spend_is_refused_at_check() {
    // The priced control: `nanocode_anthropic` under an `api_key` credential.
    let priced = || {
        std::collections::BTreeMap::from([(
            "codex".to_owned(),
            launchable_agent(
                "nanocode_anthropic",
                Some(kata_types::config::AgentCredentialDecl {
                    mode: "api_key".to_owned(),
                    source: "env:ANTHROPIC_API_KEY".to_owned(),
                }),
            ),
        )])
    };
    let unpriced = |credential: Option<kata_types::config::AgentCredentialDecl>| {
        std::collections::BTreeMap::from([(
            "keyed".to_owned(),
            launchable_agent("nanocode_openai", credential),
        )])
    };
    let pack = |agent: &str| {
        format!(
            "verdict = stage(id = \"verdict\", agent = \"{agent}\", prompt = \"review it\")\n\
             workflow(\"agent-pack\", root = [verdict], bounds = [cost_bound(0.5)])\n"
        )
    };
    let declared = |mode: &str, source: &str| {
        Some(kata_types::config::AgentCredentialDecl {
            mode: mode.to_owned(),
            source: source.to_owned(),
        })
    };
    // Each kind's own `api_key` credential, the one a recourse moves it onto.
    let api_key_of = |adapter: &str| match adapter {
        "nanocode_anthropic" => declared("api_key", "env:ANTHROPIC_API_KEY"),
        _ => declared("api_key", "env:OPENAI_API_KEY"),
    };
    let api_key = || {
        Some(kata_types::config::AgentCredentialDecl {
            mode: "api_key".to_owned(),
            source: "env:OPENAI_API_KEY".to_owned(),
        })
    };

    kata_types::node_profile::mark_node_installed();

    // The unmeterable-adapter case: `api_key` cannot save `nanocode_openai` —
    // it has no billing backend, so the bound is decoration there too — and
    // the refusal names the ADAPTER, not a subscription nobody declared.
    kata_types::node_profile::install_node_agents(unpriced(api_key()));
    let refusal = compile_starlark_execution_program(&pack("keyed"), "agent-pack.star", &[])
        .expect_err("an api_key nanocode_openai turn under a hard dollar bound refuses at CHECK")
        .to_string();
    assert!(
        refusal.contains("cost_bound_unenforceable_unpriced_adapter"),
        "the refusal is BY NAME — the unpriced adapter, not the credential: {refusal}"
    );
    recourse_is_invocable(&refusal, "run the stage on an adapter kata prices (");
    // Each adapter it offers is one this build runs: the same stage, its agent
    // moved to that kind under an `api_key` credential, is admitted under the
    // same dollar bound.
    let offered = named_kinds(&refusal, "an adapter kata prices (");
    assert_eq!(offered, ["nanocode_anthropic"], "{offered:?}");
    for adapter in &offered {
        kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
            "keyed".to_owned(),
            launchable_agent(adapter, api_key_of(adapter)),
        )]));
        compile_starlark_execution_program(&pack("keyed"), "agent-pack.star", &[]).unwrap_or_else(
            |error| {
                panic!(
                    "the refusal names `{adapter}` as an adapter kata prices, and CHECK refuses it: {error}"
                )
            },
        );
    }

    // THE EMBEDDED HARNESS under the same bound: `nanocode_openai` is unpriced
    // under its `env:` key and under kata's own login alike, by the
    // unpriced-adapter name; `nanocode_anthropic` under `api_key` is priced and
    // admitted; under `subscription` the mode door answers first.
    for (adapter, credential, refusal_name) in [
        (
            "nanocode_openai",
            declared("api_key", "env:OPENAI_API_KEY"),
            Some("cost_bound_unenforceable_unpriced_adapter"),
        ),
        (
            "nanocode_openai",
            declared("subscription", "kata_login"),
            Some("cost_bound_unenforceable_unpriced_adapter"),
        ),
        (
            "nanocode_anthropic",
            declared("subscription", "kata_login"),
            Some("credential_mode_unsupported"),
        ),
        (
            "nanocode_anthropic",
            declared("api_key", "env:ANTHROPIC_API_KEY"),
            None,
        ),
    ] {
        kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
            "nano".to_owned(),
            launchable_agent(adapter, credential.clone()),
        )]));
        let checked = compile_starlark_execution_program(&pack("nano"), "agent-pack.star", &[])
            .map(drop)
            .map_err(|error| error.to_string());
        match refusal_name {
            Some(name) => {
                let refusal = checked.expect_err(&format!(
                    "{adapter} {credential:?} under a hard dollar bound refuses at CHECK"
                ));
                assert!(
                    refusal.contains(name)
                        && refusal.contains("stage \"verdict\"")
                        && refusal.contains(&format!("`{adapter}`")),
                    "{adapter} {credential:?}: refused by name, {name}: {refusal}"
                );
                if name == "cost_bound_unenforceable_unpriced_adapter" {
                    recourse_is_invocable(&refusal, "run the stage on an adapter kata prices (");
                }
            }
            None => checked.unwrap_or_else(|refusal| {
                panic!("{adapter} {credential:?}: priced, admitted under the bound: {refusal}")
            }),
        }
    }

    // The recourse the refusal names is admitted: the same unpriceable stage
    // under a `time_bound` and no dollar bound compiles.
    kata_types::node_profile::install_node_agents(unpriced(api_key()));
    compile_starlark_execution_program(
        "verdict = stage(id = \"verdict\", agent = \"keyed\", prompt = \"review it\")\n\
         workflow(\"agent-pack\", root = [verdict], bounds = [time_bound(60000)])\n",
        "agent-pack.star",
        &[],
    )
    .expect("a time bound over unpriceable spend is the recourse the refusal names");

    // THE ADMITTED CONTROLS — the door refuses only what it claims to:
    // a priced api_key turn under the bound, and the same unmeterable
    // credential under a workflow that promises nothing about dollars.
    kata_types::node_profile::install_node_agents(priced());
    compile_starlark_execution_program(&pack("codex"), "agent-pack.star", &[]).expect(
        "an api_key nanocode_anthropic turn meters against a real rate table — the bound is \
         enforceable",
    );

    kata_types::node_profile::install_node_agents(unpriced(Some(
        kata_types::config::AgentCredentialDecl {
            mode: "subscription".to_owned(),
            source: "kata_login".to_owned(),
        },
    )));
    compile_starlark_execution_program(
        "verdict = stage(id = \"verdict\", agent = \"keyed\", prompt = \"review it\")\n\
         workflow(\"agent-pack\", root = [verdict])\n",
        "agent-pack.star",
        &[],
    )
    .expect("no hard bound in force, so an unmeterable turn owes no promise — admitted");

    // A LOOP-scope `cost_bound` covers the loop's members and gate, and only
    // them — the loop fails closed on a member of unknown cost, so the door
    // refuses the same pairings under it. `other`, outside the loop and under no
    // bound, runs the same agent and is judged first (stages walk in id order):
    // a refusal naming `w` proves `other` was admitted.
    let looped = |member: &str, loop_bounds: &str| {
        format!(
            "w = stage(id = \"w\", agent = \"{member}\", prompt = \"work\")\n\
             g = stage(id = \"g\", agent = \"shell\", run = \"true\", depends_on = [\"w\"])\n\
             loop(body = w, gate = g, max_iterations = 2{loop_bounds})\n\
             other = stage(id = \"other\", agent = \"{member}\", prompt = \"x\")\n\
             workflow(\"m\", root = [w, g, other])\n"
        )
    };
    // The same loop with the agent as its GATE and a shell body: the gate is
    // covered exactly as a body member is.
    let gated = |gate: &str| {
        format!(
            "w = stage(id = \"w\", agent = \"shell\", run = \"true\")\n\
             g = stage(id = \"g\", agent = \"{gate}\", prompt = \"judge\", depends_on = [\"w\"])\n\
             loop(body = w, gate = g, max_iterations = 2, bounds = [cost_bound(0.5)])\n\
             workflow(\"m\", root = [w, g])\n"
        )
    };
    for (agents, label, refusal_name) in [(
        unpriced(api_key()),
        "keyed",
        "cost_bound_unenforceable_unpriced_adapter",
    )] {
        kata_types::node_profile::install_node_agents(agents);
        let refusal = compile_starlark_execution_program(
            &looped(label, ", bounds = [cost_bound(0.5)]"),
            "m.star",
            &[],
        )
        .expect_err("an unpriceable loop member under the loop's cost bound refuses at CHECK")
        .to_string();
        assert!(
            refusal.contains(refusal_name)
                && refusal.contains("stage \"w\"")
                && refusal.contains("its loop's"),
            "the loop member is refused by name, the loop named as the bound's scope: {refusal}"
        );
        let refusal = compile_starlark_execution_program(&gated(label), "m.star", &[])
            .expect_err("an unpriceable loop gate under the loop's cost bound refuses at CHECK")
            .to_string();
        assert!(
            refusal.contains(refusal_name)
                && refusal.contains("stage \"g\"")
                && refusal.contains("its loop's"),
            "the loop gate is refused by name, the loop named as the bound's scope: {refusal}"
        );
        // The recourses it names hold: the same loop under a token or time bound.
        for bound in [
            ", bounds = [token_bound(1000)]",
            ", bounds = [time_bound(60000)]",
        ] {
            compile_starlark_execution_program(&looped(label, bound), "m.star", &[])
                .unwrap_or_else(|error| {
                    panic!("{label} under the loop's {bound:?} is admitted: {error}")
                });
        }
    }
    kata_types::node_profile::install_node_agents(priced());
    compile_starlark_execution_program(
        &looped("codex", ", bounds = [cost_bound(0.5)]"),
        "m.star",
        &[],
    )
    .expect("a priced api_key loop member under the loop's cost bound is admitted");

    // And the stage-scope arm: a `cost_budget("halt")` on the stage itself
    // covers it exactly as a workflow `cost_bound` does.
    kata_types::node_profile::install_node_agents(unpriced(api_key()));
    let refusal = compile_starlark_execution_program(
        "verdict = stage(id = \"verdict\", agent = \"keyed\", prompt = \"review it\", \
             cost_budget = cost_budget(\"halt\", 0.5))\n\
         workflow(\"agent-pack\", root = [verdict])\n",
        "agent-pack.star",
        &[],
    )
    .expect_err("a stage-scoped halt budget over unpriced spend refuses at CHECK")
    .to_string();
    assert!(
        refusal.contains("cost_bound_unenforceable_unpriced_adapter"),
        "the refusal is BY NAME: {refusal}"
    );
}

#[test]
fn a_parent_hard_dollar_bound_over_an_unpriced_subworkflow_child_is_refused_at_check() {
    kata_types::node_profile::mark_node_installed();
    let agent =
        |adapter: &str, mode: &str, source: &str| kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some(adapter.to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: mode.to_owned(),
                source: source.to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        };
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([
        (
            "keyed".to_owned(),
            agent("nanocode_openai", "api_key", "env:OPENAI_API_KEY"),
        ),
        (
            "nano".to_owned(),
            agent("nanocode_openai", "subscription", "kata_login"),
        ),
    ]));

    let library = tempfile::tempdir().expect("a library dir");
    let write = |name: &str, source: &str| {
        std::fs::write(library.path().join(format!("{name}.star")), source)
            .expect("write a library pack");
    };
    // The children declare NO dollar bound: judged alone, each is admitted.
    for (pack, label) in [("child_keyed", "keyed"), ("child_nanocode", "nano")] {
        write(
            pack,
            &format!(
                "verdict = stage(id = \"verdict\", agent = \"{label}\", prompt = \"review it\")\n\
                 workflow(\"{pack}\", root = [verdict])\n"
            ),
        );
    }
    write(
        "mid",
        "sub = subworkflow(id = \"sub\", pack = \"child_keyed\")\n\
         workflow(\"mid\", root = [sub], bounds = [cost_bound(0.5)])\n",
    );
    // `midfree` declares no dollar bound either: it only carries the policy down.
    write(
        "midfree",
        "sub = subworkflow(id = \"sub\", pack = \"child_keyed\")\n\
         workflow(\"midfree\", root = [sub])\n",
    );
    let libraries = [library.path().to_path_buf()];
    let parent = |pack: &str, policy: &str| {
        format!(
            "sub = subworkflow(id = \"sub\", pack = \"{pack}\")\n\
             workflow(\"parent\", root = [sub]{policy})\n"
        )
    };

    for (pack, refusal_name) in [
        ("child_keyed", "cost_bound_unenforceable_unpriced_adapter"),
        (
            "child_nanocode",
            "cost_bound_unenforceable_unpriced_adapter",
        ),
    ] {
        for policy in [
            ", bounds = [cost_bound(0.5)]",
            ", cost_budget = cost_budget(\"halt\", 0.5)",
        ] {
            let refusal = compile_starlark_execution_program(
                &parent(pack, policy),
                "parent.star",
                &libraries,
            )
            .map(|_| ())
            .expect_err(
                "a parent's hard dollar policy over a child's unpriceable spend \
                         refuses at CHECK",
            )
            .to_string();
            assert!(
                refusal.contains(refusal_name)
                    && refusal.contains(&format!("invokes subworkflow pack \"{pack}\"")),
                "the refusal names the child's arm and the invoking stage ({policy}): {refusal}"
            );
        }
        // THE ADMITTED CONTROLS: the same child under no dollar promise.
        for policy in ["", ", bounds = [time_bound(60000)]"] {
            compile_starlark_execution_program(&parent(pack, policy), "parent.star", &libraries)
                .unwrap_or_else(|error| {
                    panic!("no hard dollar policy covers the child ({policy:?}): {error}")
                });
        }
    }

    // ONE CHILD, BOTH WAYS: `a_direct` (unbounded) judges `child_keyed` first and
    // admits it; `b_bounded` reaches the same child under `mid`'s `cost_bound`.
    let refusal = compile_starlark_execution_program(
        "a_direct = subworkflow(id = \"a_direct\", pack = \"child_keyed\")\n\
         b_bounded = subworkflow(id = \"b_bounded\", pack = \"mid\")\n\
         workflow(\"root\", root = [a_direct, b_bounded])\n",
        "root.star",
        &libraries,
    )
    .map(|_| ())
    .expect_err("the bounded path to a child admitted unbounded is still judged, and refused")
    .to_string();
    assert!(
        refusal.contains("cost_bound_unenforceable_unpriced_adapter")
            && refusal.contains("stage \"b_bounded\" invokes subworkflow pack \"mid\""),
        "the refusal names the bounded path: {refusal}"
    );

    // TRANSITIVE: a parent's bound reaches a grandchild through an intermediate
    // that declares none — the runner re-roots the grandchild's unmetered stages
    // into the intermediate's summary (`MeteringSummary::absorb`), which the
    // parent's `check_metering_enforceable` reads under the parent's hard policy.
    let refusal = compile_starlark_execution_program(
        &parent("midfree", ", bounds = [cost_bound(0.5)]"),
        "parent.star",
        &libraries,
    )
    .map(|_| ())
    .expect_err("a parent's bound covers a grandchild through an unbounded intermediate")
    .to_string();
    assert!(
        refusal.contains("cost_bound_unenforceable_unpriced_adapter")
            && refusal.contains("invokes subworkflow pack \"midfree\"")
            && refusal.contains("invokes subworkflow pack \"child_keyed\""),
        "the refusal names both invoking stages on the path: {refusal}"
    );
    compile_starlark_execution_program(&parent("midfree", ""), "parent.star", &libraries)
        .expect("no hard dollar policy anywhere on the path — admitted");

    // THE STAGE-SCOPE ARM: the runner's `hard` for a subworkflow stage folds that
    // stage's own `halt` budget too. The DSL's `subworkflow()` authors none, so the
    // arm is reached through a program the door judges directly — the recovery
    // door's input.
    let mut program =
        compile_starlark_execution_program(&parent("child_keyed", ""), "parent.star", &libraries)
            .expect("no hard dollar policy covers the child");
    program
        .stages
        .get_mut(&StageId("sub".into()))
        .expect("the parent's subworkflow stage")
        .policies
        .cost_budget = kata_types::BudgetPolicy::Halt {
        limit_micro_usd: 500_000,
    };
    let refusal = kata_program::execution_program::refuse_program_at_check_or_recovery(
        &program,
        &mut std::collections::BTreeSet::new(),
    )
    .expect_err("a halt budget on the invoking stage covers its child")
    .to_string();
    assert!(
        refusal.contains("cost_bound_unenforceable_unpriced_adapter"),
        "the refusal is BY NAME: {refusal}"
    );
}

/// The loop CHECK, over the SHIPPED corpus: every pack
/// carrying a `loop(` either compiles under `oci` or is refused by a MEMBER's
/// own arm, never by the loop itself. The admitted set is pinned so a new
/// pack joining it is a conscious act: an author who ships a fourth admissible
/// loop pack names it here.
///
/// Verdicts measured against this tree:
/// * `smoke/multistage-loop-smoke`, `smoke/loop-custom-verdict-smoke`,
///   `smoke/loop-escalate-smoke` — shell members (and `multistage`'s static
///   `topology` members) over workspace views: ADMITTED.
/// * `smoke/factory-inloop-multistage-structural-smoke`,
///   `smoke/factory-loop-composition-smoke` — each carries a `workspace_effect`
///   loop MEMBER (`record`), a main-resolved member class the member door
///   serves at the member seat: ADMITTED.
/// * `smoke/review-loop-smoke`, `std/kata-loop-lite`, `std/kata-work-item`,
///   `std/kata-gate-fix-loop`, `examples/{code-review-loop, gate-fix-loop,
///   software-factory-slice}` — agent members: `adapter_undeclared`, the
///   member's own arm on a node that declares no `[agents.*]` adapter.
/// * `kata-factory/kata/factory.star` — a library file: no `workflow()` call
///   at module scope, so it produces no program under ANY profile.
#[test]
fn every_shipped_loop_pack_checks_under_oci_or_refuses_by_a_member_arm() {
    kata_types::node_profile::mark_node_installed();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workflow crate lives under <repo>/crates/workflow")
        .join("workflows");
    let roots = vec![
        repo.join("std"),
        repo.join("examples"),
        repo.join("kata-factory"),
        repo.join("smoke"),
    ];
    let mut packs = Vec::new();
    let mut stack = roots.clone();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "star")
                && std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .contains("loop(")
            {
                packs.push(path);
            }
        }
    }
    packs.sort();
    const ADMITTED: &[&str] = &[
        "smoke/factory-inloop-multistage-structural-smoke.star",
        "smoke/factory-loop-composition-smoke.star",
        "smoke/loop-custom-verdict-smoke.star",
        "smoke/loop-escalate-smoke.star",
        "smoke/multistage-loop-smoke.star",
    ];
    let mut admitted = Vec::new();
    let mut member_refusals = Vec::new();
    let mut loop_refusals = Vec::new();
    for pack in &packs {
        let rel = pack
            .strip_prefix(&repo)
            .expect("a corpus pack lives under workflows/")
            .display()
            .to_string();
        match kata_program::execution_program::compile_execution_program_from_file(pack, &roots) {
            Ok(_) => admitted.push(rel),
            Err(refusal) => {
                let text = refusal.to_string();
                if text.contains("loop_member_not_a_capsule_under_oci") {
                    member_refusals.push(rel);
                } else if text.contains("review loop") {
                    loop_refusals.push(format!("{rel}: {text}"));
                }
            }
        }
    }
    member_refusals.sort();
    assert_eq!(
        admitted,
        ADMITTED
            .iter()
            .map(|pack| (*pack).to_owned())
            .collect::<Vec<_>>(),
        "the admitted set is the pinned five — a new admission names itself here"
    );
    assert!(
        member_refusals.is_empty(),
        "no shipped loop pack refuses by the member-class token — the two \
         `workspace_effect`-member packs are admitted: {member_refusals:?}"
    );
    assert!(
        loop_refusals.is_empty(),
        "no shipped pack is refused FOR its loop — the construct is admitted: {loop_refusals:?}"
    );
}

/// `requires` at CHECK, judged against the PATH programs of the
/// environment this process BOUND (`node_profile::installed_node_environment_programs`):
/// a missing program is `environment_requirement_unmet` naming it; every
/// program present compiles; no bound environment (`None`) leaves the
/// judgement to dispatch and compiles.
#[test]
fn requires_is_judged_at_check_against_the_bound_environment() {
    kata_types::node_profile::mark_node_installed();
    let pack = "build = stage(id = \"build\", agent = \"shell\", run = \"cargo build\", \
                sandbox = sandbox_profile(workspace = \"ro\", requires = [\"cargo\", \"git\"]))\n\
                workflow(\"needs\", root = [build])\n";
    kata_types::node_profile::install_node_environment_programs(Some(
        ["git".to_owned(), "sh".to_owned()].into_iter().collect(),
    ));
    let refusal = compile_starlark_execution_program(pack, "needs.star", &[])
        .expect_err("cargo is not on the bound environment's PATH")
        .to_string();
    assert!(
        refusal.contains("environment_requirement_unmet")
            && refusal.contains("\"cargo\"")
            && !refusal.contains("\"git\""),
        "refused by name, naming exactly the missing program: {refusal}"
    );
    kata_types::node_profile::install_node_environment_programs(Some(
        ["cargo".to_owned(), "git".to_owned()].into_iter().collect(),
    ));
    compile_starlark_execution_program(pack, "needs.star", &[])
        .expect("every required program is provided");
    kata_types::node_profile::install_node_environment_programs(None);
    compile_starlark_execution_program(pack, "needs.star", &[])
        .expect("an unbound process leaves `requires` to the dispatch door");
}

/// A `requires` entry is a PROGRAM NAME: a path (which resolves
/// only on the host that authored the pack) is refused at load, and the list
/// is part of the stage's identity — two stages differing only in `requires`
/// carry different contract hashes.
#[test]
fn requires_names_programs_and_is_part_of_the_stage_identity() {
    kata_types::node_profile::mark_node_installed();
    let pack = |requires: &str| {
        format!(
            "build = stage(id = \"build\", agent = \"shell\", run = \"true\", \
             sandbox = sandbox_profile(workspace = \"ro\", requires = {requires}))\n\
             workflow(\"needs\", root = [build])\n"
        )
    };
    let refusal = compile_starlark_execution_program(&pack("[\"/usr/bin/git\"]"), "p.star", &[])
        .expect_err("a path is no program name")
        .to_string();
    assert!(
        refusal.contains("is not a program name"),
        "named: {refusal}"
    );
    let hash = |requires: &str| {
        compile_starlark_execution_program(&pack(requires), "p.star", &[])
            .expect("the pack compiles")
            .stages[&StageId(SmolStr::new("build"))]
            .contract_hash
    };
    assert_ne!(hash("[\"git\"]"), hash("[\"git\", \"cargo\"]"));
    assert_eq!(
        hash("[\"git\", \"cargo\"]"),
        hash("[\"cargo\", \"git\"]"),
        "the list is a set: order and duplicates do not change the identity"
    );
}

/// What the capsule route cannot honour is refused BY NAME at
/// CHECK under `oci`, each beside a twin that compiles: `secrets` on ANY stage
/// class's profile (a capsule carries no pack-declared secret channel for a
/// shell command OR an agent turn), `allowed_tools`, `required_capabilities`,
/// a per-stage `toolchain` pin, and `image.ref`/`image.cpus` (a capsule
/// launches no
/// per-stage image and enforces no cpu quota — `image.memory_mb` alone stays
/// honoured).
#[test]
fn the_knobs_oci_cannot_honour_are_refused_by_name() {
    kata_types::node_profile::mark_node_installed();
    let stage = |extra: &str, profile: &str| {
        format!(
            "s = stage(id = \"s\", agent = \"shell\", run = \"true\"{extra}, \
             sandbox = sandbox_profile(workspace = \"ro\"{profile}))\n\
             workflow(\"knobs\", root = [s])\n"
        )
    };
    for (extra, profile, token) in [
        (
            "",
            ", secrets = {\"TOKEN\": \"env:CI_TOKEN\"}",
            "profile_secrets_unsupported_under_oci",
        ),
        (
            ", allowed_tools = [\"Read\"]",
            "",
            "allowed_tools_unsupported_under_oci",
        ),
        (
            ", required_capabilities = [\"gpu\"]",
            "",
            "required_capabilities_unsupported_under_oci",
        ),
        (
            "",
            ", toolchain = \"store:884368bd0efb63d55b606da5a230ac6c9c5194b279647af44e4a3e73175572b7\"",
            "per_stage_toolchain_unsupported_under_oci",
        ),
        (
            "",
            ", image = {\"ref\": \"oci:test\"}",
            "per_stage_image_unsupported_under_oci",
        ),
        (
            "",
            ", image = {\"cpus\": 2}",
            "per_stage_image_unsupported_under_oci",
        ),
    ] {
        let refusal = compile_starlark_execution_program(&stage(extra, profile), "k.star", &[])
            .expect_err("an unhonourable knob is refused")
            .to_string();
        assert!(
            refusal.contains(token),
            "{token}: refused by name: {refusal}"
        );
    }
    compile_starlark_execution_program(&stage("", ""), "k.star", &[])
        .expect("the twin without the knob compiles");
    compile_starlark_execution_program(&stage("", ", image = {\"memory_mb\": 512}"), "k.star", &[])
        .expect("a memory-only image authors the honoured bound");
    // Profile `secrets` on a NON-shell class refuse under
    // the same token: an agent stage's turn has no pack-declared secret
    // channel either (its credential is the node's `[agents.<label>]`), and
    // accepting the grant would hash it and silently drop it.
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
        "codex".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    )]));
    let refusal = compile_starlark_execution_program(
        "a = stage(id = \"a\", agent = \"codex\", prompt = \"go\", \
         sandbox = sandbox_profile(workspace = \"ro\", secrets = {\"TOKEN\": \"env:CI_TOKEN\"}))\n\
         workflow(\"knobs\", root = [a])\n",
        "k.star",
        &[],
    )
    .expect_err("an agent stage's profile secrets are refused")
    .to_string();
    assert!(
        refusal.contains("profile_secrets_unsupported_under_oci"),
        "the same token, on the agent class: {refusal}"
    );
}

/// A `loop(..)` member or gate whose
/// own operation lowers to a shape the oci member door cannot serve is refused
/// BY NAME at CHECK under `oci` (`loop_member_not_a_capsule_under_oci`), judged
/// through `member_operation_is_oci_runnable` /
/// `gate_operation_is_oci_runnable` — the predicates
/// `runner::expansion::dispatch_expansion_member` routes by. A BODY member is
/// an `Execute { Command | Agent }` capsule, a nested static `topology`, or a
/// main-resolved `memory_snapshot`/`workspace_effect` — the last two serve at
/// the member seat through the top-level stages' own doors, on the head every
/// earlier member's apply landed. The refused set is exactly: `wait`
/// (a `sleep()` member or gate), `invoke`, `join` — and, at the GATE seat, the
/// two main-resolved classes (a verdict never mutates the workspace or reads
/// memory).
///
/// **Watched red:** with the door deleted the table's refused rows compile —
/// `smoke/factory-loop-composition-smoke`'s `record` member is exactly the
/// admitted `workspace_effect` row.
#[test]
fn a_loop_member_or_gate_with_no_capsule_form_is_refused_at_check_under_oci() {
    kata_types::node_profile::mark_node_installed();
    // A `sleep()` body member — `wait` has no oci member answer.
    let refusal = compile_starlark_execution_program(
        "w = stage(id = \"w\", agent = \"shell\", run = \"true\")\n\
         nap = sleep(id = \"nap\", for_ms = 50, depends_on = [\"w\"])\n\
         g = stage(id = \"g\", agent = \"shell\", run = \"true\", depends_on = [\"nap\"])\n\
         loop(body = sequence(w, nap), gate = g, max_iterations = 2)\n\
         workflow(\"m\", root = [w, g])\n",
        "m.star",
        &[],
    )
    .expect_err("a `sleep()` body member is refused")
    .to_string();
    assert!(
        refusal.contains("loop_member_not_a_capsule_under_oci"),
        "a `sleep()` body member: refused by name: {refusal}"
    );
    assert!(
        refusal.contains("`wait`"),
        "a `sleep()` body member: the refusal names the lowered tag: {refusal}"
    );
    // The main-resolved member classes COMPILE at a body member — the gate
    // seat stays capsule-only (or a static topology), judged by the narrow
    // predicate.
    for (case, member_stage, exit) in [
        (
            "a `workspace_effect` body member",
            "rec = stage(id = \"rec\", agent = \"workspace_effect\", op = \"commit\")\n",
            "rec",
        ),
        (
            "a `memory_snapshot()` body member",
            "snap = memory_snapshot(id = \"snap\")\n",
            "snap",
        ),
    ] {
        let pack = format!(
            "w = stage(id = \"w\", agent = \"shell\", run = \"true\")\n\
             {member_stage}\
             g = stage(id = \"g\", agent = \"shell\", run = \"true\", \
             depends_on = [\"{exit}\"])\n\
             loop(body = sequence(w, {exit}), gate = g, max_iterations = 2)\n\
             workflow(\"m\", root = [w, g], worktree_isolated = True)\n"
        );
        compile_starlark_execution_program(&pack, "m.star", &[])
            .unwrap_or_else(|refusal| panic!("{case} compiles under oci: {refusal}"));
    }
    // The GATE is a member too — a `sleep()` gate (which `depends_on` the body
    // exit, as the loop() rule requires) refuses by the same token, named at
    // member index 1 — and so do the main-resolved classes at the GATE seat.
    for (case, gate_stage, tag) in [
        (
            "a `sleep()` gate",
            "nap = sleep(id = \"nap\", for_ms = 50, depends_on = [\"w\"])\n",
            "wait",
        ),
        (
            "a `memory_snapshot()` gate",
            "nap = memory_snapshot(id = \"nap\", depends_on = [\"w\"])\n",
            "memory_snapshot",
        ),
        (
            "a `workspace_effect` gate",
            "nap = stage(id = \"nap\", agent = \"workspace_effect\", op = \"commit\", \
             depends_on = [\"w\"])\n",
            "execute",
        ),
    ] {
        let refusal = compile_starlark_execution_program(
            &format!(
                "w = stage(id = \"w\", agent = \"shell\", run = \"true\")\n\
                 {gate_stage}\
                 loop(body = w, gate = nap, max_iterations = 2)\n\
                 workflow(\"m\", root = [w], worktree_isolated = True)\n"
            ),
            "m.star",
            &[],
        )
        .expect_err("the gate member has no oci form either")
        .to_string();
        assert!(
            refusal.contains("loop_member_not_a_capsule_under_oci")
                && refusal.contains("\"nap\"")
                && refusal.contains("member #1")
                && refusal.contains(&format!("`{tag}`")),
            "{case}: the gate refuses by the same token at the last member: {refusal}"
        );
    }
}

/// A node-LESS CHECK (the state `kata check`, `kata workflows check
/// --all` and `kata build` run in: no `[node]`/`[agents]` facts installed) cannot
/// judge the arms that read the node's own answers, so the oci door DEFERS them
/// rather than refuse: the pack compiles, and the deferred fact classes land in
/// the `DeferredNodeFact` set the door is handed — the same set the artifact's
/// `deferred_node_facts` carries into the check surface's `not judged without a
/// booted node` line. The deferred
/// set is exactly the node's answers — the `[agents]` declarations (adapter,
/// credential pairings, the carrier doors, `cost_bound_unenforceable_*`), the
/// `[node] *_ceiling` declarations (both capsule stages here; pinned on their
/// own by `a_node_less_check_names_the_ceilings_it_did_not_judge`), `[node]
/// egress_allow`, and the bound environment's `PATH` programs. A BOOTED node —
/// an installed profile with the declarations absent — judges the same pack by
/// name.
///
/// **Watched red:** with the `!node_is_installed()` gates removed, the node-less
/// compile refuses `adapter_undeclared` and this cell's `.expect` fails.
#[test]
fn a_node_less_check_defers_the_nodes_answers_and_a_booted_node_refuses() {
    const PACK: &str = "researcher = stage(id = \"researcher\", agent = \"researcher\", \
         prompt = \"plan it\")\n\
         probe = stage(id = \"probe\", agent = \"shell\", run = \"git status\", \
         sandbox = \"s\", timeout_ms = 30000)\n\
         workflow(\"node-less-deferral\", root = [researcher, probe], \
         sandbox_profiles = {\"s\": sandbox_profile(workspace = \"ro\", net = \"host\", \
         requires = [\"git\"])})\n";

    // Node-less under `oci` — the test door: install the profile, then clear
    // the installed marker. On a flipped-default build this is what `kata
    // check` reads outright. The compiled artifact carries the deferred set —
    // the same data the check surface renders as its one `not judged without a
    // booted node:` line.
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::clear_node_installation();
    assert!(!kata_types::node_profile::node_is_installed());
    let artifact = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        PACK,
        "node-less-deferral.star",
        &[],
    )
    .expect("a node-less check defers the node facts rather than refusing");
    assert_eq!(
        artifact.deferred_node_facts,
        vec!["agents", "ceilings", "egress", "environment"],
        "the deferred note names each deferred class once"
    );

    // The BOOTED answer — an installed node whose declarations are absent
    // judges the same facts by name. Three one-stage packs isolate the arms:
    // the same stage sweep that deferred them node-less refuses them here.
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::new());
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
    let agent_pack = "researcher = stage(id = \"researcher\", agent = \"researcher\", \
         prompt = \"plan it\")\n\
         workflow(\"a\", root = [researcher])\n";
    let refusal = compile_starlark_execution_program(agent_pack, "a.star", &[])
        .expect_err("a booted node judges the agent declaration")
        .to_string();
    assert!(
        refusal.contains("adapter_undeclared") && refusal.contains("\"researcher\""),
        "the booted refusal names the agent arm: {refusal}"
    );

    let shell_pack = "probe = stage(id = \"probe\", agent = \"shell\", run = \"true\", \
         sandbox = \"s\", timeout_ms = 30000)\n\
         workflow(\"e\", root = [probe], sandbox_profiles = {\"s\": \
         sandbox_profile(workspace = \"ro\", net = \"host\")})\n";
    let refusal = compile_starlark_execution_program(shell_pack, "e.star", &[])
        .expect_err("a booted node judges the egress declaration")
        .to_string();
    assert!(
        refusal.contains("egress_undeclared") && refusal.contains("\"probe\""),
        "the booted refusal names the egress arm: {refusal}"
    );

    let requires_pack = "probe = stage(id = \"probe\", agent = \"shell\", run = \"true\", \
         sandbox = \"s\", timeout_ms = 30000)\n\
         workflow(\"r\", root = [probe], sandbox_profiles = {\"s\": \
         sandbox_profile(workspace = \"ro\", requires = [\"git\"])})\n";
    kata_types::node_profile::install_node_environment_programs(Some(
        ["cargo".to_owned()].into_iter().collect(),
    ));
    let refusal = compile_starlark_execution_program(requires_pack, "r.star", &[])
        .expect_err("a booted node judges the environment declaration")
        .to_string();
    assert!(
        refusal.contains("environment_requirement_unmet") && refusal.contains("git"),
        "the booted refusal names the environment arm: {refusal}"
    );

    // And a node-less compile of a pack carrying only AUTHORED refuseables —
    // no node facts at all — still refuses by name: deferral is scoped to the
    // node's answers, not the pack's authoring.
    kata_types::node_profile::clear_node_installation();
    let refusal = compile_starlark_execution_program(
        "w = stage(id = \"w\", agent = \"shell\", run = \"true\", sandbox = \"host\")\n\
         workflow(\"h\", root = [w])\n",
        "h.star",
        &[],
    )
    .expect_err("an authored `sandbox = \"host\"` refuses node-less — it is the pack's answer")
    .to_string();
    assert!(
        refusal.contains("host_sandbox_unsupported_under_oci"),
        "the authored refusal still fires: {refusal}"
    );
}

/// **A node-LESS CHECK names the ceilings it did not judge.** The `[node]
/// *_ceiling` declarations are the node's answer to what one stage may promise
/// and record, and an operator may raise or lower every one of them — so a
/// process that installed no node judges NO stage against them, and records
/// `ceilings` in the deferred set for every stage a ceiling door would have
/// judged. Both directions of the shipped-default guess it replaces:
///
/// * a stage authoring `output_bytes` over the shipped 1 GiB default — which a
///   node raising `output_bytes_ceiling` admits — compiles node-less, naming
///   `ceilings`, rather than being refused against a ceiling no node declared;
/// * a plain shell stage — which a node declaring a `capsule_memory_bytes_ceiling`
///   under the 512 MiB recorded default refuses — compiles node-less ONLY with
///   `ceilings` named, never silently;
/// * a pack with no capsule stage and no authored budget names none: the class
///   is named exactly when a ceiling door was skipped.
///
/// Containment is NOT a deferred class, and the cell's tail pins why: the
/// installed containment policy refuses exactly a model stage deriving
/// `HostUnconfined`, whose one authorable spelling is `sandbox = "host"` (a
/// profile name the workflow does not define is refused at load), and the
/// `oci` door refuses every process stage so spelled
/// (`host_sandbox_unsupported_under_oci`) node-less and booted alike, so no pack
/// the policy refuses passes a node-less check.
///
/// **Watched red:** at the base, the node-less compile of the over-default pack
/// refuses `capsule_budget_over_node_ceiling` and the plain shell pack's deferred
/// set is empty.
#[test]
fn a_node_less_check_names_the_ceilings_it_did_not_judge() {
    const OVER_DEFAULT: &str = "big = stage(id = \"big\", agent = \"shell\", run = \"yes\", \
         output_bytes = 2147483648)\n\
         workflow(\"over-default\", root = [big])\n";
    const PLAIN_SHELL: &str = "probe = stage(id = \"probe\", agent = \"shell\", run = \"true\")\n\
         workflow(\"plain-shell\", root = [probe])\n";
    const NO_CAPSULE: &str = "snap = memory_snapshot(id = \"snap\", kind = \"task\", \
         status = \"active\")\n\
         workflow(\"no-capsule\", root = [snap])\n";
    let node_less = |pack: &str| {
        kata_types::node_profile::mark_node_installed();
        kata_types::node_profile::clear_node_installation();
        assert!(!kata_types::node_profile::node_is_installed());
        kata_program::preflight::build_starlark_workflow_compiled_artifact(pack, "p.star", &[])
            .map(|artifact| artifact.deferred_node_facts)
            .map_err(|refusal| refusal.to_string())
    };

    assert_eq!(
        node_less(OVER_DEFAULT),
        Ok(vec!["ceilings".to_owned()]),
        "an authored budget over the shipped default is not refused node-less: ceilings named"
    );
    assert_eq!(
        node_less(PLAIN_SHELL),
        Ok(vec!["ceilings".to_owned()]),
        "a capsule stage a declared capsule ceiling could refuse passes only with ceilings named"
    );
    assert_eq!(
        node_less(NO_CAPSULE),
        Ok(Vec::<String>::new()),
        "no ceiling door judged anything, so no ceilings class is named"
    );

    // THE BOOTED ANSWER — the same packs judged against a node's own ceilings.
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            output_bytes: 1 << 32,
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    compile_starlark_execution_program(OVER_DEFAULT, "p.star", &[])
        .expect("a node raising output_bytes_ceiling to 4 GiB admits the 2 GiB stage");
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );
    let refusal = compile_starlark_execution_program(OVER_DEFAULT, "p.star", &[])
        .expect_err("a node at the shipped 1 GiB output_bytes_ceiling refuses the 2 GiB stage")
        .to_string();
    assert!(
        refusal.contains("capsule_budget_over_node_ceiling") && refusal.contains("\"big\""),
        "the booted refusal names the ceiling arm: {refusal}"
    );
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            capsule_memory_bytes: Some(256 * 1024 * 1024),
            ..kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS
        },
    );
    let refusal = compile_starlark_execution_program(PLAIN_SHELL, "p.star", &[])
        .expect_err("a node declaring a 256 MiB capsule memory ceiling refuses the 512 MiB default")
        .to_string();
    assert!(
        refusal.contains("capsule_budget_over_node_ceiling")
            && refusal.contains("capsule_memory_bytes_ceiling"),
        "the booted refusal names the recorded-bound arm: {refusal}"
    );
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::DEFAULT_NODE_BUDGET_CEILINGS,
    );

    // CONTAINMENT IS JUDGED NODE-LESS: the policy is OFF in this process, and
    // the one model stage the policy would refuse is refused anyway.
    assert!(
        !kata_types::containment_policy::installed_node_containment_policy()
            .require_contained_model_stages,
        "a node-less process observes the policy OFF"
    );
    let refusal = node_less(
        "edit = stage(id = \"edit\", agent = \"codex\", prompt = \"edit it\", \
         sandbox = \"host\")\n\
         workflow(\"h\", root = [edit])\n",
    )
    .expect_err("a model stage the containment policy refuses never passes a node-less check");
    assert!(
        refusal.contains("host_sandbox_unsupported_under_oci") && refusal.contains("\"edit\""),
        "refused by the profile's own door node-less: {refusal}"
    );
}
