//! The worker-side credential load for an [`AgentTurnSpec`].
//!
//! The capsule carries a REFERENCE — `[agents.<label>] credential = { mode,
//! source }` folded into [`kata_types::execution_contract::TurnCredentialRef`]
//! — and this module is the one place that reference becomes a credential: an
//! `env:<VAR>` API key from this worker's environment, or kata's own login
//! from the logins directory the binary names. Either is loaded into the
//! worker and carried to the embedded harness in-process
//! ([`kata_types::agent::HarnessCredential`] on the
//! [`kata_types::agent::Prompt`]); the harness's model calls leave from the
//! worker, so nothing of the credential reaches the capsule.
//!
//! # Refused set, stated
//!
//! * `credential_undeclared` — a turn that names no credential, or a declared
//!   `mode`/`source` the contract cannot read (refused at CHECK and assembly;
//!   the worker repeats it for a capsule deserialized off the wire).
//! * `credential_unavailable` — the named env var unset, holding a value that
//!   is not UTF-8 (the refusal names the variable, never the value), or one the
//!   harness's model clients cannot send: a byte below 0x20 other than a
//!   horizontal tab, or 0x7F, which no HTTP header value carries (a key
//!   exported with its trailing newline). For `kata_login`: no logins directory
//!   named ([`AgentCredentialSource::with_logins_dir`]), one the binary could
//!   not resolve (no usable effective owner home), its file absent, a directory
//!   or file that is not owner-only, a store kata did not write, no completed
//!   login, or an Anthropic subscription (no kata Claude login in this build).
//! * `credential_expired` — a ChatGPT login still expired after kata's own
//!   refresh.
//!
//! `kata_login` is the one credential kata holds itself — created only by an
//! explicit `kata login`, stored owner-only under the effective owner's home
//! (`kata_agent_nanocode::credential`), refreshed by kata, and never shared
//! with or read from another tool. Without it the turn refuses and names the
//! login command.
//!
//! Hygiene: kata's own login files are written only by `kata login` and by its
//! refresh, never by this load; no key substring ever lands in a durable row, a
//! CAS object, or a capture — the composition's cells scan for it. For
//! `kata_login` the scrub set is what the load handed out (the API key, or the
//! ChatGPT access token current at load): an access token nanocode mints by a
//! mid-turn refresh is not in it, so that token's absence from captures is not
//! covered by the scrub.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use kata_types::error::KataError;
use kata_types::execution_contract::{AgentTurnSpec, CredentialSource};
use kata_types::metering::CredentialMode;

/// The worker environment the load reads: the process environment for
/// `env:<VAR>`, and kata's own logins directory. A struct so the composition's
/// cells point both at a fixture — the production caller constructs
/// [`Self::ambient`].
#[derive(Clone, Debug)]
pub struct AgentCredentialSource {
    /// Raw bytes, as the kernel hands them: a variable need not be UTF-8.
    env: BTreeMap<OsString, OsString>,
    /// kata's OWN logins directory (`kata_agent_nanocode::credential::logins_dir`
    /// under the effective owner's home), which the BINARY names
    /// ([`Self::with_logins_dir`]): this crate never resolves a home itself.
    /// `None`, or a resolution that failed, refuses every `kata_login` source
    /// `credential_unavailable`.
    logins_dir: Option<crate::owner_home::KataLoginsDir>,
    /// The token issuer a ChatGPT login refreshes against: nanocode's own in
    /// production; a loopback mock only through the `test-support` seam.
    login_issuer: kata_agent_nanocode::credential::Issuer,
}

impl AgentCredentialSource {
    /// The production source: the process environment for `env:<VAR>`
    /// lookups.
    ///
    /// The env map is captured at construction rather than read lazily so a
    /// test asserting "the loaded key came from exactly this value" does not
    /// race a sibling test's `set_var`. It is read as raw bytes (`vars_os`):
    /// a variable that is not UTF-8 — an `env:` key's or any other — neither
    /// panics the worker nor reaches a message;
    /// [`resolve_agent_credential`] refuses such a key by the variable's name.
    #[must_use]
    pub fn ambient() -> Self {
        Self {
            env: std::env::vars_os().collect(),
            logins_dir: None,
            login_issuer: kata_agent_nanocode::credential::Issuer::default(),
        }
    }

    /// Name kata's own logins directory — the one place a `kata_login` source
    /// is read from. Each binary passes
    /// [`crate::owner_home::KataLoginsDir::resolve`], so the installed service,
    /// the CLI and a `kata-worker` daemon of one uid read the same files
    /// whatever their `HOME` says; an unresolved one refuses each `kata_login`
    /// naming why.
    #[must_use]
    pub fn with_logins_dir(mut self, logins_dir: crate::owner_home::KataLoginsDir) -> Self {
        self.logins_dir = Some(logins_dir);
        self
    }

    /// A source with `env` as its whole lookup table — the cell constructor; an
    /// ambient fallback would leak the host's real variables into a
    /// refusal-set proof.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(env: BTreeMap<String, String>) -> Self {
        Self {
            env: env
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            logins_dir: None,
            login_issuer: kata_agent_nanocode::credential::Issuer::default(),
        }
    }

    /// Point a ChatGPT login's refresh at a loopback mock issuer — the
    /// rotation cells' seam; no production path names an issuer.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_login_issuer(mut self, issuer: kata_agent_nanocode::credential::Issuer) -> Self {
        self.login_issuer = issuer;
        self
    }

    /// One env lookup — the test source's map, or ambient's.
    fn env_value(&self, var: &str) -> Option<&OsStr> {
        self.env.get(OsStr::new(var)).map(OsString::as_os_str)
    }
}

/// The whole of one dispatch's resolution.
///
/// `Debug` is NOT derived: nothing debug-prints a credential.
pub struct ResolvedAgentCredential {
    /// The harness's credential, carried to the adapter in-process.
    pub turn_credential: Option<kata_types::agent::HarnessCredential>,
    /// The credential VALUES the load handed out — the API key, or the access
    /// token current at load — for the scrub.
    lifted: Vec<String>,
}

impl ResolvedAgentCredential {
    /// Every loaded secret this resolution hands the attempt, for
    /// [`kata_types::redaction::scrub_secret_values`]. A provider can echo any
    /// of these into an error, and a refusal reason or evidence line quoting it
    /// verbatim would land the credential in a durable `worker_reason` and the
    /// warn log — so every adapter-influenced string is scrubbed through this
    /// list first.
    ///
    /// The list holds VALUES, not names: the caller must never log or persist
    /// it.
    #[must_use]
    pub fn lifted_values(&self) -> Vec<String> {
        self.lifted.clone()
    }
}

/// Resolve the turn's declared credential into the harness's in-process
/// credential.
///
/// Runs BEFORE the container launch — a refusal here is `before_the_container`,
/// and is deliberately not folded into the adapter's own refusals because the
/// load is the WORKER's act.
///
/// kata's own ChatGPT login is refreshed here when it is inside nanocode's
/// refresh window (`kata_agent_nanocode::credential`).
///
/// # Errors
/// [`KataError::Validation`] — `credential_undeclared`,
/// `credential_unavailable`, `credential_expired`.
pub fn resolve_agent_credential(
    turn: &AgentTurnSpec,
    source: &AgentCredentialSource,
) -> Result<ResolvedAgentCredential, KataError> {
    // The harness is served by the credential its turn names and nothing
    // else: a turn deserialized off the wire skipped the CHECK and the
    // assembly that refuse one naming none, so it is refused here, before the
    // container, by their name.
    let Some(reference) = turn.credential.as_ref() else {
        return Err(KataError::Validation(
            kata_types::execution_contract::harness_credential_undeclared(
                "the capsule's turn",
                turn.adapter,
            ),
        ));
    };
    match &reference.source {
        CredentialSource::EnvVar { var } => {
            let value = env_api_key(var, reference.mode, source)?;
            if !kata_agent_nanocode::HarnessAuth::is_sendable_api_key(value) {
                return Err(KataError::Validation(format!(
                    "credential_unavailable: `credential.source = \"env:{var}\"` holds a value \
                     the embedded harness cannot send: it sends the key as an HTTP header value, \
                     which admits no control character but a tab (a trailing newline, say) — \
                     the operator re-exports the key without it; kata never edits one"
                )));
            }
            Ok(ResolvedAgentCredential {
                turn_credential: Some(kata_types::agent::HarnessCredential::new(
                    kata_agent_nanocode::HarnessAuth::api_key(turn.adapter, value.to_owned()),
                )),
                lifted: vec![value.to_owned()],
            })
        }
        CredentialSource::KataLogin => resolve_kata_login(turn.adapter, reference.mode, source),
    }
}

/// An `env:<VAR>` API key's value, with the name and the mode judged first.
///
/// The name is judged here and not only at CHECK
/// (`CredentialSource::from_declared`): this reference arrives on a
/// deserialized capsule, which skips that parse.
///
/// A value that is not UTF-8 refuses `credential_unavailable` naming the
/// variable and never the value: the harness's model clients take the key as
/// text.
fn env_api_key<'a>(
    var: &str,
    mode: CredentialMode,
    source: &'a AgentCredentialSource,
) -> Result<&'a str, KataError> {
    if let Some(why) = kata_types::execution_contract::credential_env_refusal(var) {
        return Err(KataError::Validation(format!(
            "credential_undeclared: {why}"
        )));
    }
    if mode != CredentialMode::ApiKey {
        return Err(KataError::Validation(format!(
            "credential_undeclared: `credential.source = \"env:{var}\"` admits only \
             `mode = \"api_key\"` — an environment variable carries an API key, never a \
             subscription; declared mode `{}`",
            mode.as_label(),
        )));
    }
    let value = source.env_value(var).ok_or_else(|| {
        KataError::Validation(format!(
            "credential_unavailable: `credential.source = \"env:{var}\"` names a variable \
             this worker's environment does not define — the operator exports the key to the \
             worker; kata never invents one"
        ))
    })?;
    value.to_str().ok_or_else(|| {
        KataError::Validation(format!(
            "credential_unavailable: `credential.source = \"env:{var}\"` holds a value that is \
             not UTF-8, and kata carries a key only as text — the operator re-exports the key \
             as UTF-8; kata never edits one"
        ))
    })
}

/// kata's OWN login for a harness turn: the file for the kind's provider and the
/// declared mode, read from the logins directory the binary named
/// ([`AgentCredentialSource::with_logins_dir`]) and from nowhere else — never
/// another tool's login file. A ChatGPT login inside
/// nanocode's refresh window is refreshed here, before the container, under the
/// store's `flock` (`kata_agent_nanocode::credential`); one still expired after
/// that refresh refuses `credential_expired`. Every other failure — no logins
/// directory named, one the binary could not resolve, the file absent, a
/// directory or file that is not
/// owner-only, a store kata did not write, no completed login, an Anthropic
/// subscription (no kata Claude login in this build) — refuses
/// `credential_unavailable` naming the `kata login` command that writes it.
fn resolve_kata_login(
    adapter: kata_types::agent::AdapterKind,
    mode: CredentialMode,
    source: &AgentCredentialSource,
) -> Result<ResolvedAgentCredential, KataError> {
    let logins_dir = match &source.logins_dir {
        Some(crate::owner_home::KataLoginsDir::Resolved(dir)) => dir,
        Some(crate::owner_home::KataLoginsDir::Unresolved(error)) => {
            return Err(KataError::Validation(format!(
                "credential_unavailable: `credential.source = \"kata_login\"` loads kata's own \
                 login for adapter `{adapter}` from the effective owner's home, and this worker \
                 could not resolve it: {error} — kata never reads another tool's login in its \
                 place",
                adapter = adapter.as_label(),
                error = error_chain(error.as_ref()),
            )));
        }
        None => {
            return Err(KataError::Validation(format!(
                "credential_unavailable: `credential.source = \"kata_login\"` loads kata's own \
                 login for adapter `{adapter}`, and this worker names no kata logins directory \
                 to load it from — kata never reads another tool's login in its place",
                adapter = adapter.as_label(),
            )));
        }
    };
    let loaded =
        kata_agent_nanocode::credential::load(logins_dir, adapter, mode, &source.login_issuer)
            .map_err(|error| {
                KataError::Validation(format!(
                    "{refusal}: `credential.source = \"kata_login\"` for adapter `{adapter}`: \
                     {error}",
                    refusal = error.refusal(),
                    adapter = adapter.as_label(),
                ))
            })?;
    Ok(ResolvedAgentCredential {
        turn_credential: Some(kata_types::agent::HarnessCredential::new(loaded.auth)),
        lifted: loaded.scrub,
    })
}

/// `error` and each of its sources, `: `-joined.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The mock token issuer the `kata_login` rotation cells refresh against
/// (loopback only).
#[cfg(test)]
#[path = "../tests/fixtures/mock_issuer.rs"]
mod mock_issuer;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use smol_str::SmolStr;

    use super::*;
    use kata_types::agent::AdapterKind;
    use kata_types::execution_contract::{
        AgentTurnSpec, ArtifactId, CredentialSource, TurnCredentialRef,
    };
    use kata_types::primitives::ContentHash;

    fn artifact(byte: u8) -> ArtifactId {
        ArtifactId(ContentHash::new([byte; 32]))
    }

    fn turn(adapter: AdapterKind, mode: CredentialMode, source: CredentialSource) -> AgentTurnSpec {
        AgentTurnSpec {
            adapter,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: artifact(0x11),
            credential: Some(TurnCredentialRef { mode, source }),
            env: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn a_missing_env_var_refuses_credential_unavailable() {
        let source = AgentCredentialSource::for_test(BTreeMap::new());
        let error = resolve_agent_credential(
            &turn(
                AdapterKind::NanocodeOpenai,
                CredentialMode::ApiKey,
                CredentialSource::EnvVar {
                    var: SmolStr::new("ABSENT_KEY"),
                },
            ),
            &source,
        )
        .map(|_| ())
        .expect_err("a missing env var refuses");
        assert!(
            error.to_string().contains("credential_unavailable"),
            "the refusal is named: {error}"
        );
        assert!(
            error.to_string().contains("env:ABSENT_KEY"),
            "the refusal names the declared source: {error}"
        );
    }

    #[test]
    fn a_subscription_mode_pairing_wrong_for_env_is_undeclared() {
        let source = AgentCredentialSource::for_test(BTreeMap::new());
        let error = resolve_agent_credential(
            &turn(
                AdapterKind::NanocodeOpenai,
                CredentialMode::Subscription,
                CredentialSource::EnvVar {
                    var: SmolStr::new("K"),
                },
            ),
            &source,
        )
        .map(|_| ())
        .expect_err("subscription + env: refuses");
        assert!(
            error.to_string().contains("credential_undeclared"),
            "the refusal is named: {error}"
        );
    }

    /// An `env:<VAR>` name that arrives through a DESERIALIZED capsule
    /// (no `from_declared` parse in front of it) is judged here, before the
    /// lift, by the same rule the declared channel applies. The source map
    /// carries the name so the cell proves the refusal is the name check, not
    /// a missing value.
    #[test]
    fn a_deserialized_env_source_refuses_malformed_and_plumbing_owned_names() {
        for var in [
            "BAD-NAME",
            "TWO=ONE",
            "9LEADING",
            "HAS\0NUL",
            "",
            "PATH",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "HOME",
            "XDG_RUNTIME_DIR",
        ] {
            let mut env = BTreeMap::new();
            env.insert(
                var.to_owned(),
                "the-value-is-present-so-only-the-name-can-refuse".to_owned(),
            );
            let source = AgentCredentialSource::for_test(env);
            let error = resolve_agent_credential(
                &turn(
                    AdapterKind::NanocodeOpenai,
                    CredentialMode::ApiKey,
                    CredentialSource::EnvVar {
                        var: SmolStr::new(var),
                    },
                ),
                &source,
            )
            .map(|_| ())
            .expect_err("a deserialized `env:` name that CHECK would refuse refuses at the lift");
            assert!(
                error.to_string().contains("credential_undeclared"),
                "{var}: the refusal is named `credential_undeclared`: {error}"
            );
        }
    }

    /// **A nanocode turn that carries no credential is refused before the
    /// container, `credential_undeclared`, naming its login.** A capsule
    /// deserialized off the wire skips the CHECK and the assembly that refuse a
    /// nanocode block declaring none; the embedded harness runs in the worker
    /// on the credential the turn names and nothing else, so the resolver
    /// refuses the turn before anything launches, by the CHECK's name.
    ///
    /// **Would red if:** the resolver let a nanocode turn with no credential
    /// through (watched: the turn launched and the adapter refused it inside
    /// the turn, naming no login).
    #[test]
    fn a_nanocode_turn_with_no_credential_is_refused_before_the_container() {
        let source = AgentCredentialSource::for_test(BTreeMap::new());
        for adapter in AdapterKind::ALL {
            let mut spec = turn(
                adapter,
                CredentialMode::ApiKey,
                CredentialSource::EnvVar {
                    var: SmolStr::new("UNUSED"),
                },
            );
            spec.credential = None;
            let login = match adapter {
                AdapterKind::NanocodeOpenai => "`kata login openai`",
                AdapterKind::NanocodeAnthropic => "`kata login anthropic --api-key`",
            };
            let refusal = resolve_agent_credential(&spec, &source)
                .err()
                .unwrap_or_else(|| panic!("{}: resolved", adapter.as_label()))
                .to_string();
            assert!(
                refusal.contains("credential_undeclared:")
                    && refusal.contains(&format!("adapter `{}`", adapter.as_label()))
                    && refusal.contains(login),
                "{}: refused by name, naming its login: {refusal}",
                adapter.as_label()
            );
        }
    }

    /// **`env:` on a nanocode kind is carried in-process.** Both nanocode kinds
    /// load an `env:<VAR>` key into a `HarnessCredential` holding the
    /// provider's `HarnessAuth` arm; the value is in `lifted`, so every
    /// adapter-influenced string is scrubbed of it.
    ///
    /// **Would red if:** a kind's key landed in the other provider's arm, or
    /// left the scrub set.
    #[test]
    fn an_env_credential_on_a_nanocode_kind_is_carried_in_process() {
        const KEY: &str = "sk-capsule-must-not-see";
        let mut env = BTreeMap::new();
        env.insert("NANOCODE_TEST_KEY".to_owned(), KEY.to_owned());
        let source = AgentCredentialSource::for_test(env);
        let declared = CredentialSource::EnvVar {
            var: SmolStr::new("NANOCODE_TEST_KEY"),
        };
        for adapter in AdapterKind::ALL {
            let spec = turn(adapter, CredentialMode::ApiKey, declared.clone());
            let resolved = resolve_agent_credential(&spec, &source)
                .unwrap_or_else(|error| panic!("{}: env: loads: {error}", adapter.as_label()));
            assert_eq!(resolved.lifted, vec![KEY.to_owned()], "scrubbed of the key");
            let Some(harness) = resolved.turn_credential.as_ref() else {
                panic!("{}: the in-process carrier", adapter.as_label());
            };
            let auth = harness
                .downcast_ref::<kata_agent_nanocode::HarnessAuth>()
                .expect("the carrier holds the adapter's HarnessAuth");
            match (adapter, auth) {
                (AdapterKind::NanocodeOpenai, kata_agent_nanocode::HarnessAuth::OpenAi(_)) => {}
                (
                    AdapterKind::NanocodeAnthropic,
                    kata_agent_nanocode::HarnessAuth::AnthropicApiKey(key),
                ) => assert_eq!(key, KEY),
                (adapter, auth) => {
                    panic!("{}: the other provider's arm: {auth:?}", adapter.as_label())
                }
            }
        }
    }

    /// **A nanocode kind lifts exactly `kata_login` and `env:<VAR>`, and a
    /// worker that names no logins directory loads no `kata_login`.**
    /// `kata_login` refuses `credential_unavailable` (this source names no kata
    /// logins directory), on both modes the source pairs with; and `env:` under
    /// `subscription` is `credential_undeclared`.
    ///
    /// **Would red if:** `kata_login` resolved to anything on a worker with no
    /// logins directory.
    #[test]
    fn a_nanocode_kind_lifts_only_kata_login_and_env() {
        for adapter in [AdapterKind::NanocodeOpenai, AdapterKind::NanocodeAnthropic] {
            for mode in [CredentialMode::ApiKey, CredentialMode::Subscription] {
                let spec = turn(adapter, mode, CredentialSource::KataLogin);
                let error = resolve_agent_credential(
                    &spec,
                    &AgentCredentialSource::for_test(BTreeMap::new()),
                )
                .err()
                .unwrap_or_else(|| panic!("{}: kata_login loads nothing", adapter.as_label()))
                .to_string();
                assert!(error.contains("credential_unavailable"), "{error}");
                assert!(error.contains("kata_login"), "{error}");
            }
            let mut env = BTreeMap::new();
            env.insert("NANOCODE_TEST_KEY".to_owned(), "sk-x".to_owned());
            let spec = turn(
                adapter,
                CredentialMode::Subscription,
                CredentialSource::EnvVar {
                    var: SmolStr::new("NANOCODE_TEST_KEY"),
                },
            );
            let error = resolve_agent_credential(&spec, &AgentCredentialSource::for_test(env))
                .err()
                .expect("env: under subscription")
                .to_string();
            assert!(error.contains("credential_undeclared"), "{error}");
        }
    }

    /// **A nanocode kind's `env:` key is refused exactly when no HTTP header
    /// value carries it.** For both kinds, a value with each ASCII byte inside
    /// it, and three values a header carries though they look wrong (empty,
    /// spaced, non-ASCII): the lift refuses `credential_unavailable` exactly for
    /// a byte below 0x20 other than a horizontal tab, and for 0x7F, the rule
    /// spelled here byte by byte rather than by the header type the lift asks;
    /// every other value lifts into the in-process carrier. No refusal names
    /// the value.
    ///
    /// **Would red if:** the lift refused a value a header carries (a tab, a
    /// space, an empty or non-ASCII key) or handed on one it cannot (a newline,
    /// a NUL, DEL).
    #[test]
    fn a_nanocode_env_key_is_refused_exactly_when_no_header_carries_it() {
        let mut values: Vec<(String, bool)> = (0u8..=0x7f)
            .map(|byte| {
                let refused = (byte < 0x20 && byte != b'\t') || byte == 0x7f;
                (format!("key{}end", char::from(byte)), refused)
            })
            .collect();
        values.extend(
            ["", " spaced key ", "kéy"]
                .into_iter()
                .map(|value| (value.to_owned(), false)),
        );
        for adapter in [AdapterKind::NanocodeOpenai, AdapterKind::NanocodeAnthropic] {
            let spec = turn(
                adapter,
                CredentialMode::ApiKey,
                CredentialSource::EnvVar {
                    var: SmolStr::new("NANOCODE_TEST_KEY"),
                },
            );
            for (value, refused) in &values {
                let env = BTreeMap::from([("NANOCODE_TEST_KEY".to_owned(), value.clone())]);
                let lifted = resolve_agent_credential(&spec, &AgentCredentialSource::for_test(env));
                match (lifted, refused) {
                    (Err(error), true) => {
                        let error = error.to_string();
                        assert!(
                            error.starts_with("validation error: credential_unavailable:")
                                && error.contains("env:NANOCODE_TEST_KEY"),
                            "{}: {value:?}: {error}",
                            adapter.as_label()
                        );
                        assert!(!error.contains(value.as_str()), "{error}");
                    }
                    (Ok(resolved), false) => assert!(
                        resolved.turn_credential.is_some(),
                        "{}: {value:?} lifts into the in-process carrier",
                        adapter.as_label()
                    ),
                    (lifted, _) => panic!(
                        "{}: {value:?} (a header carries it: {}): {:?}",
                        adapter.as_label(),
                        !refused,
                        lifted.map(|_| "lifted").map_err(|error| error.to_string())
                    ),
                }
            }
        }
    }

    /// Write one of kata's login files as `kata login` leaves it — a 0700
    /// directory, a 0600 file — with std alone, so a cell's witness does not
    /// share the code that reads it back.
    fn write_kata_login(logins: &std::path::Path, name: &str, bytes: &str) {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(logins)
            .expect("the logins dir");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(logins.join(name))
            .and_then(|mut file| file.write_all(bytes.as_bytes()))
            .expect("the login file");
    }

    /// The bearer an OpenAI harness credential presents to the model provider.
    fn openai_bearer(resolved: &ResolvedAgentCredential) -> String {
        let Some(harness) = resolved.turn_credential.as_ref() else {
            panic!("the in-process carrier");
        };
        let Some(kata_agent_nanocode::HarnessAuth::OpenAi(auth)) =
            harness.downcast_ref::<kata_agent_nanocode::HarnessAuth>()
        else {
            panic!("the OpenAI arm");
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(auth.snapshot())
            .expect("a snapshot")
            .bearer()
            .to_owned()
    }

    /// **kata's own login is read from the logins directory the binary named,
    /// never from the environment.** The environment holds `OPENAI_API_KEY`.
    /// With the owner's logins directory named, the turn's bearer is the
    /// owner's key; with none named, the turn refuses `credential_unavailable`;
    /// and a subscription, whose file the owner never wrote, refuses naming
    /// `kata login openai`. A decoy kata API key lies under another home's
    /// `.config/kata/logins`, but nothing names that home (not the source's
    /// environment map, not `HOME`, not `with_logins_dir`), so the cell does
    /// not show another home's login unread.
    ///
    /// **Would red if:** the load fell back to the environment, or loaded with
    /// no directory named.
    #[test]
    fn a_kata_login_is_resolved_from_the_owner_home_only() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = home_dir.path().to_path_buf();
        write_kata_login(
            &kata_agent_nanocode::credential::logins_dir(&home),
            "openai-api-key",
            "sk-home-decoy\n",
        );
        let owner = tempfile::tempdir().unwrap();
        let logins = kata_agent_nanocode::credential::logins_dir(owner.path());
        write_kata_login(&logins, "openai-api-key", "sk-owner\n");
        let env = BTreeMap::from([("OPENAI_API_KEY".to_owned(), "sk-env-decoy".to_owned())]);
        let api_key = turn(
            AdapterKind::NanocodeOpenai,
            CredentialMode::ApiKey,
            CredentialSource::KataLogin,
        );

        let named = AgentCredentialSource::for_test(env.clone())
            .with_logins_dir(crate::owner_home::KataLoginsDir::Resolved(logins.clone()));
        let resolved = resolve_agent_credential(&api_key, &named).expect("the owner's key loads");
        assert_eq!(openai_bearer(&resolved), "sk-owner");
        assert_eq!(resolved.lifted, ["sk-owner"], "scrubbed of exactly the key");

        let unnamed = AgentCredentialSource::for_test(env);
        let error = resolve_agent_credential(&api_key, &unnamed)
            .err()
            .expect("no logins directory, no login")
            .to_string();
        assert!(error.contains("credential_unavailable"), "{error}");
        assert!(error.contains("names no kata logins directory"), "{error}");
        assert!(!error.contains("sk-"), "{error}");

        let subscription = turn(
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            CredentialSource::KataLogin,
        );
        let error = resolve_agent_credential(&subscription, &named)
            .err()
            .expect("the owner never logged in to ChatGPT")
            .to_string();
        assert!(error.contains("credential_unavailable"), "{error}");
        assert!(error.contains("run `kata login openai`"), "{error}");
        assert!(error.contains(&logins.display().to_string()), "{error}");
    }

    /// **An unresolved owner home refuses only `kata_login`, naming why.** A
    /// source whose binary could not resolve the effective owner's home (here
    /// an account lookup that failed with `EIO`) refuses a `kata_login` turn
    /// `credential_unavailable` naming the resolution's error and its source,
    /// under both modes; the same source still lifts an `env:` key for the same
    /// kind, so a worker without an owner home keeps serving every other
    /// source.
    ///
    /// **Would red if:** an unresolved directory refused as if none were named
    /// (the operator would not learn why), or refused a non-`kata_login`
    /// source.
    #[test]
    fn an_unresolved_owner_home_refuses_only_kata_login_naming_why() {
        let unresolved = crate::owner_home::KataLoginsDir::Unresolved(std::sync::Arc::new(
            crate::owner_home::OwnerHomeError::AccountLookup {
                uid: 4242,
                source: nix::Error::EIO,
            },
        ));
        let env = BTreeMap::from([("KATA_TEST_OPENAI_KEY".to_owned(), "sk-env".to_owned())]);
        let source = AgentCredentialSource::for_test(env).with_logins_dir(unresolved);
        for mode in [CredentialMode::ApiKey, CredentialMode::Subscription] {
            let spec = turn(
                AdapterKind::NanocodeOpenai,
                mode,
                CredentialSource::KataLogin,
            );
            let error = resolve_agent_credential(&spec, &source)
                .err()
                .expect("no owner home, no kata login")
                .to_string();
            assert!(error.contains("credential_unavailable"), "{error}");
            assert!(
                error.contains("could not resolve it: resolving the effective Kata owner account (uid 4242): EIO"),
                "{error}"
            );
        }
        let spec = turn(
            AdapterKind::NanocodeOpenai,
            CredentialMode::ApiKey,
            CredentialSource::EnvVar {
                var: "KATA_TEST_OPENAI_KEY".into(),
            },
        );
        let resolved =
            resolve_agent_credential(&spec, &source).expect("an env: key needs no owner home");
        assert_eq!(openai_bearer(&resolved), "sk-env");
    }

    /// **Two refreshes of one login file rotate it once.** Two credential
    /// sources over the SAME ChatGPT login (two loads, each its own nanocode
    /// subscription and its own open of the lock file, as two processes have)
    /// resolve at once a login whose access token is already expired, against a
    /// MOCK issuer that rotates the refresh token on each exchange, holds each
    /// rotation for 400 ms, and refuses a rotated token as reused. The issuer
    /// rotates exactly once and sees no reuse; both turns present the token
    /// that one rotation minted; and the file, read raw, holds the rotated
    /// refresh token at nanocode generation 1.
    ///
    /// **Would red if:** the refresh did not hold the store's lock across the
    /// issuer round trip, or presented a refresh token the store no longer
    /// holds (two rotations, or one refused as reuse).
    #[test]
    fn two_refreshes_of_one_file_rotate_once() {
        let issuer = mock_issuer::MockIssuer::start(
            "acct-owner",
            "rt-0",
            std::time::Duration::from_millis(400),
        );
        let owner = tempfile::tempdir().unwrap();
        let logins = kata_agent_nanocode::credential::logins_dir(owner.path());
        let local = kata_agent_nanocode::credential::Issuer::local_for_test(&issuer.url);
        kata_agent_nanocode::credential::store_chatgpt_seed_for_test(
            &logins,
            &mock_issuer::access_token("acct-owner", mock_issuer::now_secs() - 60, 0),
            "rt-0",
            "acct-owner",
            &local,
        )
        .expect("the seeded login");
        let spec = turn(
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            CredentialSource::KataLogin,
        );
        let start = std::sync::Barrier::new(2);
        let bearers = std::thread::scope(|scope| {
            let turns = [0, 1].map(|_| {
                let source = AgentCredentialSource::for_test(BTreeMap::new())
                    .with_logins_dir(crate::owner_home::KataLoginsDir::Resolved(logins.clone()))
                    .with_login_issuer(local.clone());
                let (spec, start) = (&spec, &start);
                scope.spawn(move || {
                    start.wait();
                    resolve_agent_credential(spec, &source)
                        .map(|resolved| openai_bearer(&resolved))
                        .map_err(|error| error.to_string())
                })
            });
            turns.map(|turn| turn.join().expect("the turn's thread"))
        });
        assert_eq!(
            (issuer.rotations(), issuer.reused()),
            (1, 0),
            "one rotation and no reuse: {bearers:?}"
        );
        let payload = |token: &str| token.split('.').nth(1).map(str::to_owned);
        for bearer in &bearers {
            let bearer = bearer.as_ref().expect("both turns load the login");
            let claims: serde_json::Value = serde_json::from_slice(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    payload(bearer).expect("a JWT"),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(claims["serial"], 1, "the one rotation's token: {claims}");
        }
        assert_eq!(bearers[0], bearers[1]);
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(logins.join("openai-chatgpt.json")).unwrap())
                .unwrap();
        let state: serde_json::Value =
            serde_json::from_str(stored["state"].as_str().expect("the opaque state")).unwrap();
        assert_eq!(state["credential"]["refresh_token"], "rt-1", "{state}");
        assert_eq!(state["credential"]["generation"], 1, "{state}");
    }

    /// The variable whose value the non-UTF-8 cell plants as an `env:` key.
    const NON_UTF8_KEY_VAR: &str = "KATA_NON_UTF8_TEST_KEY";
    /// The variable whose value the non-UTF-8 cell plants as no credential at all.
    const NON_UTF8_OTHER_VAR: &str = "KATA_NON_UTF8_TEST_OTHER";
    /// Marks the re-exec'd child run, holding its data directory.
    const NON_UTF8_CHILD: &str = "KATA_NON_UTF8_TEST_CHILD";

    /// **A worker whose environment holds a variable that is not UTF-8 admits
    /// its capsule route, refuses an `env:` key holding one by the VARIABLE's
    /// name, and never prints the value.** The cell re-execs this test binary
    /// with two planted non-UTF-8 values — an `env:` key and a variable no
    /// source names — because the workspace denies the `unsafe` `set_var`. The
    /// child admits the capsule route on a fresh data directory (no provider is
    /// declared, so it refuses `oci_provider_undeclared` before it opens
    /// anything there) and lifts the key for every adapter kind from the
    /// ambient source. The parent then reads the outcome out of the process:
    /// the child exited zero with no panic, each refusal it printed is
    /// `credential_unavailable` naming `env:KATA_NON_UTF8_TEST_KEY`, and the
    /// planted marker appears in neither its stdout nor its stderr — so no
    /// refusal text a caller records holds it.
    ///
    /// **Would red if:** the source read the environment through
    /// `std::env::vars()` (it panics on the first such variable at admission,
    /// printing the value), or refused the key under another name or printed
    /// its value.
    #[test]
    fn a_non_utf8_environment_admits_and_refuses_the_key_by_name_without_its_value() {
        use std::os::unix::ffi::OsStrExt;

        const KEY_VALUE: &[u8] = b"sk-u22-PLANTED\xff";
        const OTHER_VALUE: &[u8] = b"u22-other-PLANTED\xfe";
        const MARKER: &[u8] = b"PLANTED";

        if let Some(data_dir) = std::env::var_os(NON_UTF8_CHILD) {
            return non_utf8_child(&PathBuf::from(data_dir));
        }
        let root = tempfile::tempdir().expect("a scratch root");
        let data_dir = root.path().join("data");
        std::fs::create_dir(&data_dir).expect("the data directory");
        let test = format!(
            "{}::a_non_utf8_environment_admits_and_refuses_the_key_by_name_without_its_value",
            module_path!()
                .split_once("::")
                .map_or(module_path!(), |(_, path)| path)
        );
        let mut child = std::process::Command::new(
            std::env::current_exe().expect("the test binary's own path"),
        );
        child
            .args(["--exact", &test, "--nocapture", "--test-threads", "1"])
            .env(NON_UTF8_CHILD, &data_dir)
            .env(NON_UTF8_KEY_VAR, std::ffi::OsStr::from_bytes(KEY_VALUE))
            .env(NON_UTF8_OTHER_VAR, std::ffi::OsStr::from_bytes(OTHER_VALUE));
        for key in crate::provider_store::NODE_PROVIDER_ENV_KEYS {
            child.env_remove(key);
        }
        let output = child.output().expect("the child test run spawns");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && !stderr.contains("panicked"),
            "the child run must exit zero without a panic (exit {:?})\n--- stdout ---\n{stdout}\n\
             --- stderr ---\n{stderr}",
            output.status.code(),
        );
        for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                !bytes.windows(MARKER.len()).any(|window| window == MARKER),
                "the child's {stream} holds a planted value:\n{}",
                String::from_utf8_lossy(bytes)
            );
        }
        let refusals = stdout
            .lines()
            .filter(|line| line.starts_with("refusal: "))
            .collect::<Vec<_>>();
        assert_eq!(
            refusals.len(),
            AdapterKind::ALL.len(),
            "one printed refusal per adapter kind:\n{stdout}"
        );
        for line in refusals {
            assert!(
                line.starts_with(
                    "refusal: validation error: credential_unavailable: `credential.source = \
                     \"env:KATA_NON_UTF8_TEST_KEY\"` holds a value that is not UTF-8"
                ),
                "{line}"
            );
        }
    }

    /// The re-exec'd half of the non-UTF-8 cell: every step the worker takes
    /// with this environment, each refusal printed for the parent to scan.
    fn non_utf8_child(data_dir: &std::path::Path) {
        let refused = crate::capsule_route::CapsuleRoute::admit_for(
            data_dir,
            crate::owner_home::KataLoginsDir::Resolved(PathBuf::from("/nonexistent/logins")),
        )
        .map(|_| ())
        .expect_err("no provider is declared, so the admission refuses");
        println!("admission: {refused}");
        assert!(
            refused
                .to_string()
                .contains(crate::capsule_route::OCI_PROVIDER_UNDECLARED),
            "{refused}"
        );
        let source = AgentCredentialSource::ambient();
        for adapter in AdapterKind::ALL {
            let error = resolve_agent_credential(
                &turn(
                    adapter,
                    CredentialMode::ApiKey,
                    CredentialSource::EnvVar {
                        var: SmolStr::new(NON_UTF8_KEY_VAR),
                    },
                ),
                &source,
            )
            .map(|_| ())
            .expect_err("a key that is not UTF-8 refuses");
            println!("refusal: {error}");
        }
    }
}
