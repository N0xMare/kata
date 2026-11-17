//! This build's EXECUTOR TERM: the capsule reuse key's commitment to what
//! kata's own machinery does to a stage.
//!
//! [`kata_types::execution_platform::ExecutorTerm`] is the fold and states the
//! rule; this module supplies its properties, because the bytes they describe —
//! the OCI bundle renderer and the youki certification — live in this crate.
//! Boot (`bin/kata`'s `BootRig::boot`) derives the term once through
//! [`node_executor_term`] and installs it on the stage-cache store, where the
//! runner's capsule reuse consult reads it to key the hint it looks up and records.
//! A standalone `kata-worker` daemon derives its OWN through the same function and
//! states it on Hello (`kata_transport::enrollment::EnrollmentProbe::executor_term`).
//!
//! # The six properties, each the exact bytes kata hands the runtime, the capsule or the harness
//!
//! | Property | Bytes | Why these and not a version |
//! |---|---|---|
//! | `oci_seccomp_rules` | the JSON of [`oci_seccomp_rules`] — the `linux.seccomp` every capsule's `config.json` carries | a deny-list edit moves it; a release that leaves the list alone does not |
//! | `youki_binary_sha256` | the pinned youki's sha256, as `config/youki-pin.toml` states it | [`crate::oci_runtime::certified_oci_route`] refuses a binary whose bytes do not hash to it, and [`crate::oci_runtime::verify_pinned_youki_unchanged`] re-checks it before every launch — so it IS the content hash of every runtime that starts a capsule container. Never the pinned path or the version string: a rebuild with new bytes under one version moves it |
//! | `oci_bundle_template_command` | the `config.json` [`crate::oci_bundle::spec_for_as`] renders for a fixed OFFLINE COMMAND reference capsule | every byte the renderer contributes on its own — namespaces, capabilities, masked and read-only paths, the `/proc` and `/dev` mounts, rlimits, the id mapping's shape, mount options — moves it; the per-capsule fields are held fixed by the reference |
//! | `oci_bundle_template_toolhost` | the `config.json` rendered for a fixed AGENT reference capsule — every agent capsule's init is `kata-toolhost` — with an egress allowlist, a git view and a declared env | the arms the command reference does not take — the `createContainer` egress hooks and proxy env, the `/git-history` and `/git` binds, the agent's env layout, the read-only `/.kata` bind and its mount point, the fixed `process.args`, the rendered `HOME` — move it |
//! | `tool_host` | `kata-toolhost/<TOOLHOST_PROTOCOL_VERSION>/<TOOLHOST_SOURCE_DIGEST>`, `kata_toolhost_protocol`'s two constants | the program a nanocode capsule's every tool call runs through: a protocol change or any byte of the in-tree source the toolhost compiles in (the toolhost, its wire and the frame codec the wire re-exports from `kata-provider-protocol`; `crates/toolhost-protocol/build.rs` names the roots) moves it |
//! | `agent_harness` | the JSON of `kata_agent_nanocode::harness_identity`: the pinned nanocode rev, the digest of the Code Mode engine as kata runs it — the vendored engine, kata's patch to it and kata's interpreter host (`kata_agent_nanocode::CODE_MODE_ENGINE_DIGEST`) —, the digest of the interpreter's syscall filter as compiled (`kata_code_mode_host::syscall_filter_digest`), the Code Mode limits, and each backend's host tool definitions (rendered over an inert host) and the instructions kata gives it | the embedded harness a nanocode turn runs in the worker: a nanocode bump (which carries every text nanocode renders on its own), any byte of the vendored engine, of its patch or of the interpreter host's manifest or source (`crates/agent-nanocode/build.rs` names the roots), a change to the interpreter's syscall filter (from its list, kata's seccomp compiler or `libc`'s numbers), a limit change, or a change to a model-facing tool definition or to kata's own instructions moves it |
//!
//! # What the term does NOT cover, stated
//!
//! * **Which kind of capsule a property applies to.** The term is ONE node-wide
//!   digest, folded into every capsule's reuse key: a command capsule's key folds
//!   the toolhost template, `tool_host` and `agent_harness` too, though
//!   none of them touches a command capsule, so a change to any of them misses
//!   every capsule once (a toolhost doc edit missed every shell stage's reuse).
//!   Keying each capsule by only the properties of its own kind would need a term
//!   per kind through every place the one term travels: a `kata-worker` daemon
//!   states it on Hello, the main stamps the delivering registration's term onto
//!   every accepted capsule result (the durable `executor_term` of the
//!   acceptance outcome, which reuse compares), and the stage cache installs
//!   it. That is a change to a durable stamp's meaning, not to this module, and
//!   these misses are deliberate, rare, one-time ones (a toolhost source change,
//!   a nanocode bump), the cost every toolhost-template or seccomp change
//!   already pays.
//! * **The embedded harness beyond `agent_harness`'s facts.** nanocode's own
//!   prompts and code are covered only through its pinned rev, and the Code
//!   Mode engine as kata runs it (its guard, the interpreter process a cell runs
//!   in, and what each reports to the model and the evidence) through its two
//!   digests; nanocode's dependency versions, the engine's and the interpreter
//!   host's included, not at all, nor the choices outside those roots that put
//!   a cell in an interpreter process at all (`install_code_mode_limits`'s
//!   backend, each binary's dispatch), which cells pin.
//!
//! * **What is not a byte of `config.json`, beyond the tool host's source.** The
//!   provider entry that hands the bundle to youki — `kata-provider-youki`, the
//!   `kata-oci-hook` program the egress hooks exec and the `kata-toolhost` BYTES a
//!   nanocode capsule execs — which the node's provider declaration names by content
//!   address (`crate::provider_store`), not this build: `tool_host` folds the source
//!   digest this build expects, and the toolhost's `Hello` states its own, a
//!   self-report that catches a mismatched build and not a dishonest one. The
//!   toolhost's dependency versions (tokio, rustix) are in neither. The worker's
//!   credential load (`crate::agent_credential`) renders nothing into a bundle:
//!   the harness's credential is carried to the harness in-process.
//! * **A renderer branch keyed on a per-capsule value the references hold fixed.**
//!   Each reference takes one value of every input (one closure entry, one access
//!   tag per mapping, one allowlist entry); a change confined to how the renderer
//!   treats a value neither reference carries moves no byte of either.
//! * **Which worker runs a capsule.** The key folds the MAIN's term, and a capsule
//!   the main places on a `kata-worker` daemon runs under THAT daemon's fence. The
//!   daemon states its term on Hello, the main stamps the delivering registration's
//!   term onto every accepted capsule result, and capsule reuse records and serves
//!   only a result stamped with the main's own term — so a daemon of another build
//!   still takes work, and its results never seed or serve the cache. Placement does
//!   not read the term.
//! * **Anything the term is not a property of.** The kernel, the host's AppArmor
//!   profile text, cgroup delegation: host facts, measured by the certification and
//!   refused there, never keyed.

use kata_toolhost_protocol::{TOOLHOST_PROTOCOL_VERSION, TOOLHOST_SOURCE_DIGEST};
use kata_types::{
    KataError, KataResult,
    execution_platform::ExecutorTerm,
    sandbox_seccomp::{OciSeccompRules, oci_seccomp_rules},
    youki_pin::YoukiPin,
};

/// The rendered OCI seccomp rules.
const SECCOMP_RULES_PROPERTY: &str = "oci_seccomp_rules";
/// The pinned youki binary's content hash.
const YOUKI_BINARY_PROPERTY: &str = "youki_binary_sha256";
/// The command reference capsule's rendered `config.json`.
const COMMAND_TEMPLATE_PROPERTY: &str = "oci_bundle_template_command";
/// The toolhost reference capsule's rendered `config.json`.
const TOOLHOST_TEMPLATE_PROPERTY: &str = "oci_bundle_template_toolhost";
/// The tool host's protocol number and source digest.
const TOOL_HOST_PROPERTY: &str = "tool_host";
/// The embedded harness's identity (`kata_agent_nanocode::harness_identity`).
const AGENT_HARNESS_PROPERTY: &str = "agent_harness";

/// This build's executor term — see the module docs.
///
/// Host-independent by construction: every input is a constant of the build (the
/// deny-list, the embedded pin, the renderer over two fixed references with a fixed
/// uid/gid, the toolhost's protocol number and compiled source digest, and the
/// harness's identity over an inert host), so every host derives the same term from
/// one binary, and the derivation performs no I/O.
///
/// # Errors
///
/// A build defect only: the fence has no OCI form, the embedded pin does not parse,
/// the renderer refuses one of its own reference capsules, or the harness's identity
/// does not render. A node that hits one has no capsule route either.
pub fn node_executor_term() -> KataResult<ExecutorTerm> {
    fold(&node_properties()?)
}

/// The six inputs [`properties`] names.
struct Facts<'a> {
    seccomp_rules: &'a OciSeccompRules,
    youki_sha256: &'a str,
    command_template: &'a str,
    toolhost_template: &'a str,
    tool_host: &'a str,
    agent_harness: &'a str,
}

/// The `tool_host` property's bytes for a protocol number and a source digest.
fn tool_host(protocol: u32, source_digest: &str) -> String {
    format!("kata-toolhost/{protocol}/{source_digest}")
}

/// The `agent_harness` property's bytes: the harness's identity as JSON.
fn agent_harness() -> KataResult<String> {
    kata_agent_nanocode::harness_identity()
        .and_then(|identity| serde_json::to_string(&identity).map_err(|error| error.to_string()))
        .map_err(|error| {
            KataError::Validation(format!(
                "the executor term cannot fold the embedded harness: {error}"
            ))
        })
}

/// This build's six properties, named — what [`node_executor_term`] folds.
fn node_properties() -> KataResult<[(&'static str, Vec<u8>); 6]> {
    let rules = oci_seccomp_rules().map_err(|refusal| {
        KataError::Validation(format!(
            "the executor term cannot fold the seccomp fence: {refusal}"
        ))
    })?;
    let pin = YoukiPin::embedded_result().map_err(|error| {
        KataError::Validation(format!(
            "the executor term cannot fold the pinned youki: {error}"
        ))
    })?;
    properties(&Facts {
        seccomp_rules: &rules,
        youki_sha256: pin.sha256(),
        command_template: &crate::oci_bundle::reference_command_config()?,
        toolhost_template: &crate::oci_bundle::reference_toolhost_config()?,
        tool_host: &tool_host(TOOLHOST_PROTOCOL_VERSION, TOOLHOST_SOURCE_DIGEST),
        agent_harness: &agent_harness()?,
    })
}

fn properties(facts: &Facts<'_>) -> KataResult<[(&'static str, Vec<u8>); 6]> {
    let rules = serde_json::to_vec(facts.seccomp_rules).map_err(|error| {
        KataError::Validation(format!(
            "the executor term cannot serialize the seccomp rules: {error}"
        ))
    })?;
    Ok([
        (SECCOMP_RULES_PROPERTY, rules),
        (
            YOUKI_BINARY_PROPERTY,
            facts.youki_sha256.as_bytes().to_vec(),
        ),
        (
            COMMAND_TEMPLATE_PROPERTY,
            facts.command_template.as_bytes().to_vec(),
        ),
        (
            TOOLHOST_TEMPLATE_PROPERTY,
            facts.toolhost_template.as_bytes().to_vec(),
        ),
        (TOOL_HOST_PROPERTY, facts.tool_host.as_bytes().to_vec()),
        (
            AGENT_HARNESS_PROPERTY,
            facts.agent_harness.as_bytes().to_vec(),
        ),
    ])
}

fn fold(properties: &[(&'static str, Vec<u8>)]) -> KataResult<ExecutorTerm> {
    let borrowed: Vec<(&str, &[u8])> = properties
        .iter()
        .map(|(name, value)| (*name, value.as_slice()))
        .collect();
    ExecutorTerm::derive(&borrowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_types::execution_contract::{
        ArtifactId, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess, EnvironmentId,
        GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformId, PreparedActionId,
    };
    use kata_types::primitives::ContentHash;
    use kata_types::sandbox_seccomp::{DENIED_SYSCALLS, rules_for};

    /// One capsule, to show a term change reaches a REUSE KEY and not only a term.
    fn capsule() -> Capsule {
        let fixed = |byte: u8| ContentHash::new([byte; 32]);
        let mapping = |path: &str, artifact: u8| GuestMapping {
            artifact: ArtifactId(fixed(artifact)),
            guest_path: GuestPath::new(path.to_owned()).unwrap(),
            access: GuestAccess::ReadWrite,
        };
        Capsule::new(
            OccurrenceId(fixed(1)),
            PreparedActionId(fixed(2)),
            EnvironmentId(fixed(3)),
            PlatformId(fixed(4)),
            vec![mapping("/work", 5), mapping("/out", 6), mapping("/tmp", 7)],
            CapsuleProcess::Command {
                argv: vec![smol_str::SmolStr::new("true")],
            },
            CapsuleNetwork::Offline,
            None,
            CapsuleBudgets {
                wall_time_ms: 30_000,
                output_bytes: 1 << 20,
                memory_bytes: 512 << 20,
                process_count: 64,
                result_bytes: 4 << 20,
                result_entries: 128,
                work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
                work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
            },
            None,
        )
        .unwrap()
    }

    /// The term over explicit facts — [`node_executor_term`]'s fold, with each input
    /// a parameter so a cell can move exactly one.
    fn term(facts: &Facts<'_>) -> ExecutorTerm {
        fold(&properties(facts).unwrap()).unwrap()
    }

    /// This build's six facts, owned, for a cell to move one of.
    struct Shipped {
        rules: OciSeccompRules,
        command: String,
        toolhost: String,
        tool_host: String,
        agent_harness: String,
    }

    impl Shipped {
        fn new() -> Self {
            Self {
                rules: oci_seccomp_rules().unwrap(),
                command: crate::oci_bundle::reference_command_config().unwrap(),
                toolhost: crate::oci_bundle::reference_toolhost_config().unwrap(),
                tool_host: tool_host(TOOLHOST_PROTOCOL_VERSION, TOOLHOST_SOURCE_DIGEST),
                agent_harness: agent_harness().unwrap(),
            }
        }

        fn facts(&self) -> Facts<'_> {
            Facts {
                seccomp_rules: &self.rules,
                youki_sha256: YoukiPin::embedded().sha256(),
                command_template: &self.command,
                toolhost_template: &self.toolhost,
                tool_host: &self.tool_host,
                agent_harness: &self.agent_harness,
            }
        }
    }

    /// **A DENY-LIST CHANGE IS A MISS.** The shipped fence and the same fence one
    /// entry shorter — the kata upgrade the term exists for — derive two terms,
    /// so one capsule answers two reuse keys.
    ///
    /// **Would red if:** the seccomp rules left the term (the upgraded node would
    /// adopt a result produced under the other fence).
    #[test]
    fn a_changed_deny_list_moves_the_reuse_key() {
        let shipped = Shipped::new();
        let narrowed = rules_for(&DENIED_SYSCALLS[1..]).unwrap();
        assert_ne!(
            shipped.rules, narrowed,
            "the counterfactual moves the rules"
        );
        let after = term(&Facts {
            seccomp_rules: &narrowed,
            ..shipped.facts()
        });
        assert_ne!(
            capsule().reuse_key(&term(&shipped.facts())),
            capsule().reuse_key(&after)
        );
    }

    /// **A YOUKI WITH OTHER BYTES IS A MISS.** Two binaries' content hashes derive
    /// two terms, whatever version string either carries — the version is not an
    /// input at all.
    ///
    /// **Would red if:** the youki property left the term. (That the node's property
    /// is the pin's CONTENT hash and not its version or path is
    /// `the_node_term_is_pinned_and_carries_no_version_string`'s subject.)
    #[test]
    fn a_changed_youki_binary_moves_the_reuse_key() {
        let shipped = Shipped::new();
        let rebuilt = "0".repeat(64);
        assert_ne!(shipped.facts().youki_sha256, rebuilt);
        let after = term(&Facts {
            youki_sha256: &rebuilt,
            ..shipped.facts()
        });
        assert_ne!(
            capsule().reuse_key(&term(&shipped.facts())),
            capsule().reuse_key(&after)
        );
    }

    /// **A BUNDLE-TEMPLATE CHANGE IS A MISS, in either reference** — one moved
    /// byte of the command or toolhost reference's `config.json` (a mount option
    /// dropped, say) derives another term.
    ///
    /// **Would red if:** any template left the term.
    #[test]
    fn a_changed_bundle_template_moves_the_reuse_key() {
        let shipped = Shipped::new();
        let before = capsule().reuse_key(&term(&shipped.facts()));
        for (which, template) in [
            ("command", &shipped.command),
            ("toolhost", &shipped.toolhost),
        ] {
            assert!(
                template.contains("\"nosuid\""),
                "{which}: the counterfactual edits a real option"
            );
            let edited = template.replacen("\"nosuid\",", "", 1);
            let after = match which {
                "command" => term(&Facts {
                    command_template: &edited,
                    ..shipped.facts()
                }),
                _ => term(&Facts {
                    toolhost_template: &edited,
                    ..shipped.facts()
                }),
            };
            assert_ne!(before, capsule().reuse_key(&after), "{which}");
        }
    }

    /// **A TOOL HOST OF ANOTHER SOURCE OR PROTOCOL IS A MISS.** The shipped
    /// `tool_host` property and the same with another source digest, and with the
    /// next protocol number, derive three terms; the property is exactly the
    /// protocol crate's two constants, so a changed byte of the source the
    /// toolhost compiles in reaches every reuse key. That such a byte moves
    /// `TOOLHOST_SOURCE_DIGEST` is that crate's
    /// `the_source_digest_is_the_blake3_of_the_source_as_built` (the compiled
    /// digest equals a blake3 over every file of the toolhost's in-tree closure)
    /// with `the_roots_are_the_toolhosts_in_tree_closure` (the roots are that
    /// closure).
    ///
    /// **Would red if:** the toolhost's digest or protocol left the term.
    #[test]
    fn the_toolhost_source_moves_the_term() {
        let shipped = Shipped::new();
        assert_eq!(
            shipped.tool_host,
            format!("kata-toolhost/{TOOLHOST_PROTOCOL_VERSION}/{TOOLHOST_SOURCE_DIGEST}")
        );
        let before = capsule().reuse_key(&term(&shipped.facts()));
        let other_source = tool_host(TOOLHOST_PROTOCOL_VERSION, &"0".repeat(64));
        let other_protocol = tool_host(TOOLHOST_PROTOCOL_VERSION + 1, TOOLHOST_SOURCE_DIGEST);
        let keys: Vec<_> = [&other_source, &other_protocol]
            .into_iter()
            .map(|moved| {
                capsule().reuse_key(&term(&Facts {
                    tool_host: moved,
                    ..shipped.facts()
                }))
            })
            .collect();
        assert_ne!(keys[0], before, "another source digest");
        assert_ne!(keys[1], before, "another protocol");
        assert_ne!(keys[0], keys[1]);
    }

    /// **THE EMBEDDED HARNESS IS IN THE TERM.** The shipped `agent_harness` bytes
    /// name the pinned nanocode rev, the Code Mode engine's digest, the
    /// interpreter's syscall filter digest and kata's Code Mode limits, and carry
    /// each backend's host tool definitions as nanocode renders them (codex's
    /// named exactly `HOST_SET_CODEX`, claude's `HOST_SET_CLAUDE`). Each of these
    /// moved on its own (another rev, another engine digest, another filter
    /// digest, another memory limit, another tool description, another capsule
    /// statement) derives another term, so one capsule answers a different reuse
    /// key.
    ///
    /// **Would red if:** `agent_harness` left the term, or the shipped identity
    /// lost the rev, a digest, the memory limit or a host tool definition. The
    /// edits below CREATE a key that is absent, so this cell cannot see a fact
    /// that left the identity; `kata-agent-nanocode`'s
    /// `the_harness_identity_carries_every_fact_at_its_shipped_value` pins that,
    /// and the pinned term literal catches any change of its bytes.
    #[test]
    fn the_agent_harness_moves_the_term() {
        let shipped = Shipped::new();
        let identity: serde_json::Value = serde_json::from_str(&shipped.agent_harness).unwrap();
        assert_eq!(
            identity["nanocode_rev"],
            serde_json::json!(kata_agent_nanocode::NANOCODE_REV)
        );
        assert_eq!(
            identity["code_mode_engine_digest"],
            serde_json::json!(kata_agent_nanocode::CODE_MODE_ENGINE_DIGEST)
        );
        assert_eq!(
            identity["code_mode_syscall_filter_digest"],
            serde_json::json!(kata_code_mode_host::syscall_filter_digest().unwrap())
        );
        assert_eq!(
            identity["code_mode_limits"]["memory_bytes"],
            serde_json::json!(kata_agent_nanocode::CODE_MODE_LIMITS.memory_bytes)
        );
        for (backend, pinned) in [
            ("codex", &kata_agent_nanocode::HOST_SET_CODEX[..]),
            ("claude", &kata_agent_nanocode::HOST_SET_CLAUDE[..]),
        ] {
            let mut names: Vec<&str> = identity[backend]["tool_definitions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|definition| definition["name"].as_str().unwrap())
                .collect();
            names.sort_unstable();
            let mut pinned = pinned.to_vec();
            pinned.sort_unstable();
            assert_eq!(names, pinned, "{backend}'s tool definitions");
        }
        let before = capsule().reuse_key(&term(&shipped.facts()));
        let moved = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut identity = identity.clone();
            edit(&mut identity);
            let bytes = serde_json::to_string(&identity).unwrap();
            assert_ne!(
                bytes, shipped.agent_harness,
                "the counterfactual moves a fact"
            );
            capsule().reuse_key(&term(&Facts {
                agent_harness: &bytes,
                ..shipped.facts()
            }))
        };
        let keys = [
            moved(&|identity| identity["nanocode_rev"] = serde_json::json!("0".repeat(40))),
            moved(&|identity| {
                identity["code_mode_engine_digest"] = serde_json::json!("0".repeat(64));
            }),
            moved(&|identity| {
                identity["code_mode_syscall_filter_digest"] = serde_json::json!("0".repeat(64));
            }),
            moved(&|identity| {
                identity["code_mode_limits"]["memory_bytes"] = serde_json::json!(1_u64 << 20);
            }),
            moved(&|identity| {
                identity["codex"]["tool_definitions"][0]["description"] =
                    serde_json::json!("another description");
            }),
            moved(&|identity| {
                identity["codex"]["instructions"]["capsule_statement"] =
                    serde_json::json!("another statement");
            }),
        ];
        for (which, key) in [
            "rev",
            "engine digest",
            "filter digest",
            "limit",
            "tool definition",
            "instructions",
        ]
        .iter()
        .zip(&keys)
        {
            assert_ne!(*key, before, "another {which}");
        }
    }

    /// **THE TOOLHOST REFERENCE TAKES EVERY ARM THE COMMAND REFERENCE DOES NOT** —
    /// read out of the rendered JSON, not out of the inputs: the two
    /// `createContainer` egress hooks, the proxy env, the declared env entry, the
    /// `/git-history` and `/git` binds, and the toolhost arm (the `/.kata` bind,
    /// `process.args` `["/.kata/kata-toolhost"]`, `HOME=/tmp`). Each is a render arm
    /// a change to which must move the term, which it does only while a reference
    /// takes it.
    ///
    /// **Would red if:** a reference stopped declaring one of its arms, so a change
    /// confined to that arm's render would move no key again.
    #[test]
    fn the_toolhost_reference_takes_every_arm_the_command_reference_does_not() {
        let shipped = Shipped::new();
        // (reference, template, takes the agent arms)
        for (which, template, agent) in [
            ("command", &shipped.command, false),
            ("toolhost", &shipped.toolhost, true),
        ] {
            let config: serde_json::Value = serde_json::from_str(template).unwrap();
            let hooks = config["hooks"]["createContainer"]
                .as_array()
                .map_or(0, Vec::len);
            let env: Vec<&str> = config["process"]["env"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            let destinations: Vec<&str> = config["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|mount| mount["destination"].as_str())
                .collect();
            let arms = [
                ("egress hooks", hooks == 2, agent),
                (
                    "proxy env",
                    env.iter().any(|entry| entry.starts_with("HTTP_PROXY=")),
                    agent,
                ),
                ("declared env", env.contains(&"TERM=dumb"), agent),
                (
                    "git history bind",
                    destinations.contains(&"/git-history"),
                    agent,
                ),
                ("git scratch bind", destinations.contains(&"/git"), agent),
                ("toolhost bind", destinations.contains(&"/.kata"), agent),
                (
                    "toolhost launch",
                    config["process"]["args"] == serde_json::json!(["/.kata/kata-toolhost"]),
                    agent,
                ),
                ("toolhost HOME", env.contains(&"HOME=/tmp"), agent),
            ];
            for (arm, taken, expected) in arms {
                assert_eq!(taken, expected, "{which} reference, arm {arm}: {template}");
            }
        }
    }

    /// **THIS BUILD'S TERM, PINNED — and no property carries the version string.**
    ///
    /// The literal is host-independent (every input is a build constant), so it is
    /// the same on every host in the gate. It moves exactly when the fence, the
    /// pinned youki, either bundle template, the tool host (its protocol
    /// or any byte of its, its wire's or its frame codec's source) or the embedded
    /// harness (its rev, the vendored Code Mode engine, its patch or kata's
    /// interpreter host, the interpreter's syscall filter, its Code Mode limits, a
    /// tool definition or kata's instructions) moves — each a deliberate, one-time,
    /// cache-wide miss whose re-pin a reviewer reads — and NOT when only the kata
    /// version string does: no property is a function of it, which the second half
    /// asserts by name and by bytes.
    ///
    /// **Would red if:** a property folded `CARGO_PKG_VERSION` (or any seventh
    /// property joined unannounced), or any of the six facts moved.
    #[test]
    fn the_node_term_is_pinned_and_carries_no_version_string() {
        let properties = node_properties().unwrap();
        let names: Vec<&str> = properties.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                SECCOMP_RULES_PROPERTY,
                YOUKI_BINARY_PROPERTY,
                COMMAND_TEMPLATE_PROPERTY,
                TOOLHOST_TEMPLATE_PROPERTY,
                TOOL_HOST_PROPERTY,
                AGENT_HARNESS_PROPERTY,
            ]
        );
        // The version as a TOKEN: not inside a longer dotted number, so the toolhost
        // reference's `127.0.0.1` proxy address is not read as version `0.0.1`.
        let version = env!("CARGO_PKG_VERSION").as_bytes();
        let numeric = |byte: Option<&u8>| byte.is_some_and(|b| b.is_ascii_digit() || *b == b'.');
        for (name, value) in &properties {
            let carried = (0..=value.len().saturating_sub(version.len())).any(|at| {
                value[at..].starts_with(version)
                    && !numeric(at.checked_sub(1).and_then(|before| value.get(before)))
                    && !numeric(value.get(at + version.len()))
            });
            assert!(
                !carried,
                "property {name} carries this build's version string {:?}",
                env!("CARGO_PKG_VERSION")
            );
        }
        assert_eq!(
            node_executor_term().unwrap().digest().to_string(),
            "7b65a69b9604ceec65b5e578aed35551bcab94452b941b59a3d0e83fded3dd09",
            "this build's executor term moved: re-pin ONLY after naming which fact moved \
             (fence, youki, command or toolhost template, tool host, agent harness) — \
             every capsule reuse key on every node misses once"
        );
    }
}
