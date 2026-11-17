//! Mint, verify, and wire-encode scoped [`ApiToken`]s.
//!
//! This is the application-layer authorization for the REST API. In
//! place of a single flat shared bearer secret — which any holder, including the
//! workload itself, could present to authorize *every* route — a caller presents
//! a token that the **main's ed25519 signing key minted**, carrying an
//! authenticated [`kata_types::identity::ApiScope`]. The API verifies that
//! signature against the main's verifying key on every request and
//! authorizes the route by the token's scope, so a holder can neither forge a
//! token nor escalate its own scope.
//!
//! The signature is computed over [`ApiToken::signing_payload`] — the
//! domain-separated, length-prefixed canonical encoding of every field except
//! the signature itself, using a domain distinct from the worker-credential
//! signing context (cross-protocol signature-confusion defense). See
//! [`crate::credential`] for the sibling worker-credential helpers this mirrors.
//!
//! The **wire form** ([`encode_api_token`] / [`decode_api_token`]) is
//! URL-safe-base64-no-pad over the token's JSON encoding: a single
//! whitespace-free string suitable for an `Authorization: Bearer <token>`
//! header.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use kata_types::identity::{ApiScope, ApiToken};
use kata_types::{FixedBytes, KataError, KataResult};
use smol_str::SmolStr;

use crate::sign::{Signature, SigningKey, VerifyingKey};

/// Sign `token` in place with the main's `signing_key`, populating
/// [`ApiToken::signature`] with an ed25519 signature over
/// [`ApiToken::signing_payload`].
///
/// Any pre-existing signature is overwritten. The payload excludes the signature
/// field, so signing is idempotent (re-signing yields the same signature for the
/// same key).
pub fn sign_api_token(signing_key: &SigningKey, token: &mut ApiToken) {
    let payload = token.signing_payload();
    let signature = signing_key.sign(&payload);
    token.signature = FixedBytes::new(signature.to_bytes());
}

/// Construct and sign a scoped [`ApiToken`] in one step.
///
/// The main calls this to mint a token for a given `scope` and `issued_for`
/// label. `expires_at == None` mints a non-expiring token.
#[must_use]
pub fn mint_api_token(
    signing_key: &SigningKey,
    scope: ApiScope,
    issued_for: impl Into<SmolStr>,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> ApiToken {
    let mut token = ApiToken {
        scope,
        issued_for: issued_for.into(),
        issued_at,
        expires_at,
        signature: FixedBytes::zero(),
    };
    sign_api_token(signing_key, &mut token);
    token
}

/// Verify a presented API token at the API's authentication boundary.
///
/// Returns `Ok(())` only if **all** checks pass, else a
/// [`KataError::Authentication`]. The cryptographic signature is validated
/// *first* — no claimed field (least of all [`ApiToken::scope`]) is trusted until
/// the token is proven authentic.
///
/// 1. **Signature** — ed25519 verify of [`ApiToken::signing_payload`] under
///    `verifying_key`. Rejects forged or tampered tokens (any altered bound
///    field — including the scope — breaks the signature) and tokens signed by a
///    key other than `verifying_key`.
/// 2. **Validity window** — `now` must be `>= issued_at`, and `<= expires_at`
///    when an expiry is set. A `None` expiry never expires.
pub fn verify_api_token(
    verifying_key: &VerifyingKey,
    token: &ApiToken,
    now: DateTime<Utc>,
) -> KataResult<()> {
    // 1. Signature — authenticate before trusting any claimed field.
    let payload = token.signing_payload();
    let signature = Signature::from_bytes(token.signature.0);
    verifying_key.verify(&payload, &signature).map_err(|_| {
        // Collapse the underlying crypto error into a hard, non-retryable
        // authentication failure; never leak which byte failed.
        KataError::Authentication("api token signature is invalid".to_string())
    })?;

    // 2. Validity window.
    if now < token.issued_at {
        return Err(KataError::Authentication(
            "api token is not yet valid (issued_at is in the future)".to_string(),
        ));
    }
    if let Some(expires_at) = token.expires_at
        && now > expires_at
    {
        return Err(KataError::Authentication(
            "api token has expired".to_string(),
        ));
    }

    Ok(())
}

/// Encode a token to its `Authorization: Bearer` wire form: URL-safe base64
/// (no padding) over the token's JSON encoding. The result is a single
/// whitespace-free string.
///
/// # Panics
///
/// Never in practice — [`ApiToken`] is a plain serde struct with an infallible
/// JSON encoding; the `expect` documents that invariant.
#[must_use]
pub fn encode_api_token(token: &ApiToken) -> String {
    let json = serde_json::to_vec(token).expect("ApiToken serializes to JSON");
    URL_SAFE_NO_PAD.encode(json)
}

/// Decode a token from its [`encode_api_token`] wire form. A malformed base64 or
/// JSON body is a [`KataError::Authentication`] (an unreadable token is
/// indistinguishable from a bad one at the trust boundary — fail closed).
pub fn decode_api_token(encoded: &str) -> KataResult<ApiToken> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim().as_bytes())
        .map_err(|_| KataError::Authentication("api token is not valid base64".to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| KataError::Authentication("api token is not a valid token".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{Duration, TimeZone as _};

    fn issued_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn expires_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_003_600, 0).unwrap()
    }

    fn valid_now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_001_800, 0).unwrap()
    }

    fn mint(seed: u8, scope: ApiScope, expiry: Option<DateTime<Utc>>) -> (SigningKey, ApiToken) {
        let sk = SigningKey::from_seed([seed; 32]);
        let token = mint_api_token(&sk, scope, "test", issued_at(), expiry);
        (sk, token)
    }

    #[test]
    fn roundtrip_sign_then_verify_succeeds() {
        let (sk, token) = mint(0x01, ApiScope::Operate, Some(expires_at()));
        verify_api_token(&sk.verifying_key(), &token, valid_now())
            .expect("a freshly-minted token must verify");
    }

    #[test]
    fn signing_is_idempotent() {
        let (sk, mut token) = mint(0x02, ApiScope::Approve, None);
        let first = token.signature;
        sign_api_token(&sk, &mut token);
        assert_eq!(first, token.signature);
    }

    #[test]
    fn scope_escalation_after_signing_is_rejected() {
        // The core attack: a holder rewrites Operate → Approve on an
        // otherwise-valid token. The scope is bound, so the signature breaks.
        let (sk, mut token) = mint(0x03, ApiScope::Operate, Some(expires_at()));
        token.scope = ApiScope::Approve;
        let err = verify_api_token(&sk.verifying_key(), &token, valid_now())
            .expect_err("rewriting the scope must break the signature");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
        assert!(err.to_string().contains("signature is invalid"));
    }

    #[test]
    fn wrong_signer_key_is_rejected() {
        let (_sk, token) = mint(0x04, ApiScope::Admin, Some(expires_at()));
        let attacker = SigningKey::from_seed([0xAA; 32]);
        let err = verify_api_token(&attacker.verifying_key(), &token, valid_now())
            .expect_err("a token verified against the wrong key must be rejected");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
    }

    #[test]
    fn forged_token_signed_by_attacker_is_rejected() {
        // Attacker mints their own Admin token and presents it to an API that
        // verifies against the real home key. The signature check fails.
        let attacker = SigningKey::from_seed([0xBB; 32]);
        let forged = mint_api_token(
            &attacker,
            ApiScope::Admin,
            "attacker",
            issued_at(),
            Some(expires_at()),
        );
        let real_home = SigningKey::from_seed([0x10; 32]);
        let err = verify_api_token(&real_home.verifying_key(), &forged, valid_now())
            .expect_err("a token not signed by the home key must be rejected");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
    }

    #[test]
    fn expired_token_is_rejected() {
        let (sk, token) = mint(0x05, ApiScope::Operate, Some(expires_at()));
        let after = expires_at() + Duration::seconds(1);
        let err = verify_api_token(&sk.verifying_key(), &token, after)
            .expect_err("an expired token must be rejected");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn not_yet_valid_token_is_rejected() {
        let (sk, token) = mint(0x06, ApiScope::Operate, Some(expires_at()));
        let before = issued_at() - Duration::seconds(1);
        let err = verify_api_token(&sk.verifying_key(), &token, before)
            .expect_err("a not-yet-valid token must be rejected");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
        assert!(err.to_string().contains("not yet valid"));
    }

    #[test]
    fn non_expiring_token_verifies_far_in_the_future() {
        let (sk, token) = mint(0x07, ApiScope::Operate, None);
        let far_future = Utc.timestamp_opt(4_000_000_000, 0).unwrap();
        verify_api_token(&sk.verifying_key(), &token, far_future)
            .expect("a None-expiry token never expires");
    }

    #[test]
    fn wire_form_roundtrips_and_is_whitespace_free() {
        let (_sk, token) = mint(0x08, ApiScope::Approve, Some(expires_at()));
        let encoded = encode_api_token(&token);
        assert!(
            !encoded.chars().any(char::is_whitespace),
            "bearer token must be whitespace-free: {encoded:?}"
        );
        let decoded = decode_api_token(&encoded).expect("wire form round-trips");
        assert_eq!(decoded, token);
    }

    #[test]
    fn decode_rejects_garbage() {
        let err = decode_api_token("!!!not base64!!!").expect_err("garbage must not decode");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
        // Valid base64, invalid JSON.
        let not_json = URL_SAFE_NO_PAD.encode(b"not a token");
        let err = decode_api_token(&not_json).expect_err("non-token JSON must not decode");
        assert!(matches!(err, KataError::Authentication(_)), "got {err:?}");
    }
}
