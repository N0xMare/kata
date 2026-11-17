//! Integration coverage for `kata_client`'s top-level constructor
//! contract.
//!
//! The tests use only the SDK's public surface (`KataClient::new`, `KataClient::base_url`,
//! `KataClientError`) so no `testing` shim is required.

use kata_client::{KataClient, KataClientError};

#[test]
fn new_rejects_garbage_url() {
    let err = KataClient::new("not a url").unwrap_err();
    assert!(matches!(err, KataClientError::InvalidBaseUrl(_)));
}

#[test]
fn new_strips_trailing_slash() {
    let c = KataClient::new("http://127.0.0.1:8400/").unwrap();
    assert_eq!(c.base_url(), "http://127.0.0.1:8400");
}

#[test]
fn new_accepts_http_url() {
    let c = KataClient::new("http://127.0.0.1:8400").unwrap();
    assert_eq!(c.base_url(), "http://127.0.0.1:8400");
}

#[test]
fn with_bearer_token_rejects_empty_token() {
    let err = KataClient::with_bearer_token("http://127.0.0.1:8400", " \n").unwrap_err();
    assert!(matches!(err, KataClientError::InvalidAuthToken(_)));
}

#[test]
fn with_bearer_token_rejects_whitespace_token() {
    let err = KataClient::with_bearer_token("http://127.0.0.1:8400", "abc def").unwrap_err();
    assert!(matches!(err, KataClientError::InvalidAuthToken(_)));
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "lib_tests/phantom_binary_guard.rs"]
mod phantom_binary_guard;
#[path = "lib_tests/secrets_redaction_tests.rs"]
mod secrets_redaction_tests;
#[path = "lib_tests/system_tests.rs"]
mod system_tests;
#[path = "lib_tests/workflow_tests.rs"]
mod workflow_tests;
