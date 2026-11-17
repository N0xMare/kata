//! Executable form of the secrets-handling review checklist for the SDK
//! surface.
//!
//! Each `checklist_*` test corresponds to one machine-checkable line of that
//! checklist. The shared property under test is that a secret a
//! caller can supply through the SDK — today, a credential embedded in the
//! base URL's userinfo (`scheme://user:secret@host`) — is refused
//! fail-closed and is **never** rendered into an error message, a log line,
//! or a crash/`Debug` dump.

use kata_client::KataClient;
use kata_client::error::{DiagnosticContextValue, KataClientError};

/// A distinctive secret we can grep for. If it ever shows up in rendered
/// output, redaction failed.
const SECRET: &str = "s3cr3t-token-do-not-leak-9d4f";

/// A base URL that carries a credential in its userinfo is
/// refused, and the refusal is a `SecretInBaseUrl` redaction marker rather
/// than the raw URL. This is the production error path the redaction type
/// now guards.
#[test]
fn secret_in_base_url_is_refused_with_a_redaction_marker() {
    let url = format!("http://admin:{SECRET}@127.0.0.1:8400");
    let err = KataClient::new(&url).expect_err("a URL userinfo credential must be refused");
    match err {
        KataClientError::SecretInBaseUrl(DiagnosticContextValue::SecretRedacted { name }) => {
            assert_eq!(name, "base_url_userinfo");
        }
        other => panic!("expected SecretInBaseUrl redaction marker, got {other:?}"),
    }
}

/// A username-only URL (no password) is still a credential and is refused
/// the same way — the check keys on either half of the userinfo.
#[test]
fn username_only_userinfo_is_also_refused() {
    let url = format!("http://{SECRET}@127.0.0.1:8400");
    let err = KataClient::new(&url).expect_err("a username-only userinfo must be refused");
    assert!(
        matches!(err, KataClientError::SecretInBaseUrl(_)),
        "{err:?}"
    );
}

/// Every SDK constructor funnels through the same sanitizer, so the
/// bearer-token and env-token entry points refuse the embedded secret too.
#[test]
fn all_constructors_refuse_embedded_url_credentials() {
    let url = format!("https://user:{SECRET}@127.0.0.1:8400");
    assert!(matches!(
        KataClient::new(&url),
        Err(KataClientError::SecretInBaseUrl(_))
    ));
    assert!(matches!(
        KataClient::with_bearer_token(&url, "some-token"),
        Err(KataClientError::SecretInBaseUrl(_))
    ));
    assert!(matches!(
        KataClient::new_with_env_token(&url),
        Err(KataClientError::SecretInBaseUrl(_))
    ));
}

/// Checklist lines 1 & 2: "Grep every log
/// line for secret leakage" and "Grep error messages and panics for the
/// same." The rendered `Display` of the error (exactly what a `tracing`
/// `%err` field or an operator-facing message prints) must not contain the
/// secret.
#[test]
fn checklist_error_messages_and_logs_do_not_leak_url_secret() {
    let url = format!("http://admin:{SECRET}@127.0.0.1:8400");
    let err = KataClient::new(&url).expect_err("must refuse");

    let display = format!("{err}");
    assert!(
        !display.contains(SECRET),
        "Display rendering leaked the secret: {display}"
    );
    // The message must still be actionable — it names the redacted field.
    assert!(
        display.contains("base_url_userinfo"),
        "Display should name the redacted field: {display}"
    );
}

/// Checklist line 3: "Verify crash dumps
/// redact secrets." A panic / crash dump renders errors with `Debug`
/// (`{:?}`, `.unwrap()`, `.expect()`), so the `Debug` form must be
/// secret-free as well.
#[test]
fn checklist_crash_dump_debug_redacts_secret() {
    let url = format!("http://admin:{SECRET}@127.0.0.1:8400");
    let err = KataClient::new(&url).expect_err("must refuse");

    let debug = format!("{err:?}");
    assert!(
        !debug.contains(SECRET),
        "Debug (crash-dump) rendering leaked the secret: {debug}"
    );

    // The redaction marker itself is secret-safe by construction: it stores
    // only a field label, never the value.
    let marker = DiagnosticContextValue::SecretRedacted {
        name: "base_url_userinfo".to_string(),
    };
    assert!(!format!("{marker:?}").contains(SECRET));
}

/// A well-formed URL with no embedded credential is accepted unchanged
/// (the sanitizer only rejects userinfo; it does not break normal use),
/// and the trailing-slash normalization still holds.
#[test]
fn clean_base_url_is_accepted_and_normalized() {
    let client = KataClient::new("http://127.0.0.1:8400/").expect("clean URL must be accepted");
    assert_eq!(client.base_url(), "http://127.0.0.1:8400");
}
