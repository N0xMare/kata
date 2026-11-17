//! Tests for `crates/types/src/error.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::error::{ErrorSeverity, KataError};
use kata_types::test_support::json_roundtrip;

#[test]
fn severity_is_total_for_all_variants() {
    // One representative per variant.
    let cases: Vec<(KataError, ErrorSeverity)> = vec![
        (KataError::Config("c".into()), ErrorSeverity::Expected),
        (
            KataError::Serialization("s".into()),
            ErrorSeverity::Expected,
        ),
        (
            KataError::Io(std::io::Error::other("io")),
            ErrorSeverity::Transient,
        ),
        (KataError::Crypto("k".into()), ErrorSeverity::Degraded),
        (KataError::Storage("db".into()), ErrorSeverity::Fatal),
        (KataError::Network("n".into()), ErrorSeverity::Transient),
        (KataError::Protocol("p".into()), ErrorSeverity::Degraded),
        (KataError::Validation("v".into()), ErrorSeverity::Expected),
        (KataError::Timeout("t".into()), ErrorSeverity::Transient),
        (
            KataError::OutcomeUnknown("unknown".into()),
            ErrorSeverity::Degraded,
        ),
        (
            KataError::Authentication("a".into()),
            ErrorSeverity::Degraded,
        ),
        (KataError::Internal("i".into()), ErrorSeverity::Fatal),
    ];
    for (err, expected) in cases {
        assert_eq!(err.severity(), expected, "mismatch for {err:?}");
    }
}

#[test]
fn severity_roundtrips_json() {
    for sev in ErrorSeverity::ALL {
        json_roundtrip(sev);
    }
}

#[test]
fn severity_ordering_matches_repr() {
    assert!(ErrorSeverity::Expected < ErrorSeverity::Transient);
    assert!(ErrorSeverity::Transient < ErrorSeverity::Degraded);
    assert!(ErrorSeverity::Degraded < ErrorSeverity::Fatal);
}
