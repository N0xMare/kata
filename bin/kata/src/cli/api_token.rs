//! `kata api-token mint` — operator command to mint scoped, ed25519-signed API
//! bearer tokens.
//!
//! `SignedToken` API auth is un-deployable without a way to mint tokens: the
//! API verifies each request's `Authorization: Bearer <token>` against the main
//! node's PUBLIC verifying key, and this command is how the operator produces
//! those tokens from the paired PRIVATE signing key. It routes through the same
//! [`kata_crypto::mint_api_token`] primitive the runtime would, and prints the
//! [`kata_crypto::encode_api_token`] wire form so the scope carried by the token
//! is authenticated by the signature (a holder can neither forge nor escalate).

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use kata_crypto::{SigningKey, encode_api_token, mint_api_token};
use kata_types::config::validate_shared_secret_file_permissions;

use super::types::{ApiTokenCmd, CliApiScope};

/// Environment variable read for the hex-encoded ed25519 signing key when
/// `--signing-key-file` is not supplied. Signing keys are operator CLI inputs,
/// not daemon configuration.
const SIGNING_KEY_ENV: &str = "KATA_API_SIGNING_KEY";

/// Dispatch `kata api-token <cmd>`.
pub fn run_api_token_cmd(cmd: ApiTokenCmd) -> Result<()> {
    match cmd {
        ApiTokenCmd::Mint {
            scope,
            signing_key_file,
            issued_for,
            expires_in,
        } => run_mint(
            scope,
            signing_key_file.as_deref(),
            &issued_for,
            expires_in.as_deref(),
        ),
    }
}

fn run_mint(
    scope: CliApiScope,
    signing_key_file: Option<&Path>,
    issued_for: &str,
    expires_in: Option<&str>,
) -> Result<()> {
    let signing_key = load_signing_key(signing_key_file)?;
    let encoded = mint_encoded_token(
        scope,
        &signing_key,
        issued_for,
        expires_in,
        chrono::Utc::now(),
    )?;
    println!("{encoded}");
    Ok(())
}

/// Mint + encode a scoped token to its bearer wire form. Split from
/// [`run_mint`]'s stdout print so the mint→decode round-trip is unit-testable.
fn mint_encoded_token(
    scope: CliApiScope,
    signing_key: &SigningKey,
    issued_for: &str,
    expires_in: Option<&str>,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> Result<String> {
    refuse_an_unnormal_issued_for(issued_for)?;
    let expires_at = match expires_in {
        Some(spec) => Some(issued_at + parse_expires_in(spec)?),
        None => None,
    };
    let token = mint_api_token(signing_key, scope.into(), issued_for, issued_at, expires_at);
    Ok(encode_api_token(&token))
}

/// Refuse a `--issued-for` that is blank or carries leading or trailing whitespace.
///
/// The label is the principal a signed-token main attributes a stop discharge to,
/// compared trimmed against the request's `operator`: a blank one names no one, and a
/// padded one would sign a label other than the one the operator types.
fn refuse_an_unnormal_issued_for(issued_for: &str) -> Result<()> {
    if issued_for.trim().is_empty() {
        bail!(
            "--issued-for is blank: a token's label names the principal it is issued for, so \
             pass a non-blank one, e.g. --issued-for ci-bot"
        );
    }
    if issued_for.trim() != issued_for {
        bail!(
            "--issued-for {issued_for:?} has leading or trailing whitespace: pass the label \
             itself, {:?}",
            issued_for.trim()
        );
    }
    Ok(())
}

/// Resolve the signing key from `--signing-key-file` (credential material —
/// permission-checked and treated exactly like the main identity key) or, when
/// absent, from `KATA_API_SIGNING_KEY`.
fn load_signing_key(signing_key_file: Option<&Path>) -> Result<SigningKey> {
    let hex_str = match signing_key_file {
        Some(path) => {
            validate_shared_secret_file_permissions(path, "api signing key")
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read api signing key at {}", path.display()))?
        }
        None => std::env::var(SIGNING_KEY_ENV).map_err(|_| {
            anyhow::anyhow!(
                "no signing key configured: pass --signing-key-file <path> or set \
                 {SIGNING_KEY_ENV} (a hex-encoded 32-byte ed25519 private key)"
            )
        })?,
    };
    parse_signing_key_hex(hex_str.trim())
}

fn parse_signing_key_hex(hex_str: &str) -> Result<SigningKey> {
    if hex_str.is_empty() {
        bail!("api signing key is empty");
    }
    let mut seed = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut seed)
        .context("api signing key must be 64 hex chars (a 32-byte ed25519 private key)")?;
    Ok(SigningKey::from_seed(seed))
}

/// Parse a compact validity window like `30d`, `12h`, `90m`, or `3600s` into a
/// [`chrono::Duration`]. Deliberately tiny — no external humantime dependency —
/// covering the four units an operator needs for a token TTL.
fn parse_expires_in(spec: &str) -> Result<chrono::Duration> {
    let spec = spec.trim();
    let (value, unit_secs): (&str, i64) = if let Some(rest) = spec.strip_suffix('d') {
        (rest, 86_400)
    } else if let Some(rest) = spec.strip_suffix('h') {
        (rest, 3_600)
    } else if let Some(rest) = spec.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = spec.strip_suffix('s') {
        (rest, 1)
    } else {
        bail!(
            "--expires-in '{spec}' must end in a unit: d(ays), h(ours), m(inutes), \
             or s(econds), e.g. 30d"
        );
    };
    let amount: i64 = value.trim().parse().map_err(|_| {
        anyhow::anyhow!("--expires-in '{spec}' has a non-integer amount before its unit")
    })?;
    if amount <= 0 {
        bail!("--expires-in '{spec}' must be a positive duration");
    }
    let secs = amount.checked_mul(unit_secs).ok_or_else(|| {
        anyhow::anyhow!("--expires-in '{spec}' overflows the representable duration range")
    })?;
    Ok(chrono::Duration::seconds(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser as _;
    use kata_crypto::{decode_api_token, verify_api_token};
    use kata_types::identity::ApiScope;

    use crate::cli::{Cli, Command};

    #[test]
    fn cli_parses_api_token_mint() {
        let cli = Cli::try_parse_from([
            "kata",
            "api-token",
            "mint",
            "--scope",
            "approve",
            "--signing-key-file",
            "/tmp/api-signing-key",
            "--issued-for",
            "ci-bot",
            "--expires-in",
            "30d",
        ])
        .expect("api-token mint must parse");
        let Command::ApiToken {
            cmd:
                ApiTokenCmd::Mint {
                    scope,
                    signing_key_file,
                    issued_for,
                    expires_in,
                },
        } = cli.command
        else {
            panic!("expected api-token mint, got {:?}", cli.command);
        };
        assert_eq!(scope, CliApiScope::Approve);
        assert_eq!(
            signing_key_file.as_deref(),
            Some(Path::new("/tmp/api-signing-key"))
        );
        assert_eq!(issued_for, "ci-bot");
        assert_eq!(expires_in.as_deref(), Some("30d"));
    }

    #[test]
    fn mint_requires_scope() {
        assert!(
            Cli::try_parse_from(["kata", "api-token", "mint"]).is_err(),
            "--scope is required"
        );
    }

    #[test]
    fn issued_for_defaults_and_expiry_is_optional() {
        let cli = Cli::try_parse_from(["kata", "api-token", "mint", "--scope", "operate"])
            .expect("scope-only mint must parse");
        let Command::ApiToken {
            cmd:
                ApiTokenCmd::Mint {
                    scope,
                    signing_key_file,
                    issued_for,
                    expires_in,
                },
        } = cli.command
        else {
            panic!("expected api-token mint");
        };
        assert_eq!(scope, CliApiScope::Operate);
        assert!(signing_key_file.is_none());
        assert_eq!(issued_for, "operator-cli");
        assert!(expires_in.is_none());
    }

    #[test]
    fn minted_token_round_trips_and_verifies_under_paired_key() {
        // The core property: a token minted here verifies under the
        // PAIRED verifying key (the public half the API is configured with) and
        // carries the requested, signature-bound scope.
        let signing_key = SigningKey::from_seed([9u8; 32]);
        let issued_at = chrono::Utc::now();

        let encoded = mint_encoded_token(
            CliApiScope::Approve,
            &signing_key,
            "operator-cli",
            Some("1h"),
            issued_at,
        )
        .expect("mint must succeed");

        let token = decode_api_token(&encoded).expect("printed bearer wire form must decode");
        assert_eq!(
            token.scope,
            ApiScope::Approve,
            "scope must survive the round-trip"
        );
        assert_eq!(token.issued_for, "operator-cli");
        assert!(
            token.expires_at.is_some(),
            "an --expires-in token must carry an expiry"
        );

        verify_api_token(&signing_key.verifying_key(), &token, issued_at)
            .expect("minted token must verify under the paired verifying key");

        // A different key must NOT verify it — proves the signature is real.
        let other = SigningKey::from_seed([0xAB; 32]);
        assert!(
            verify_api_token(&other.verifying_key(), &token, issued_at).is_err(),
            "token must not verify under an unrelated key"
        );
    }

    /// A token's `issued_for` is the principal a signed-token main attributes its stop
    /// discharges to, compared trimmed against the request's `operator`. A blank label
    /// names no one and a padded one is not the label it signs, so mint refuses both by
    /// name and signs nothing.
    #[test]
    fn mint_refuses_a_blank_or_padded_issued_for() {
        let signing_key = SigningKey::from_seed([5u8; 32]);
        for label in ["", "   ", " ci-bot", "ci-bot\t", "\nci-bot"] {
            let refusal = mint_encoded_token(
                CliApiScope::Approve,
                &signing_key,
                label,
                None,
                chrono::Utc::now(),
            )
            .expect_err("a blank or padded label is refused");
            assert!(
                refusal.to_string().contains("--issued-for"),
                "the refusal names the flag for {label:?}: {refusal}"
            );
        }
        mint_encoded_token(
            CliApiScope::Approve,
            &signing_key,
            "ci bot",
            None,
            chrono::Utc::now(),
        )
        .expect("an inner space is part of the label");
    }

    #[test]
    fn non_expiring_token_round_trips() {
        let signing_key = SigningKey::from_seed([4u8; 32]);
        let issued_at = chrono::Utc::now();
        let encoded = mint_encoded_token(
            CliApiScope::Operate,
            &signing_key,
            "mcp-agent",
            None,
            issued_at,
        )
        .expect("mint must succeed");
        let token = decode_api_token(&encoded).unwrap();
        assert!(token.expires_at.is_none(), "no --expires-in ⇒ non-expiring");
        assert_eq!(token.scope, ApiScope::Operate);
    }

    #[test]
    fn parse_expires_in_accepts_all_units() {
        assert_eq!(parse_expires_in("30d").unwrap(), chrono::Duration::days(30));
        assert_eq!(
            parse_expires_in("12h").unwrap(),
            chrono::Duration::hours(12)
        );
        assert_eq!(
            parse_expires_in("90m").unwrap(),
            chrono::Duration::minutes(90)
        );
        assert_eq!(
            parse_expires_in("45s").unwrap(),
            chrono::Duration::seconds(45)
        );
    }

    #[test]
    fn parse_expires_in_rejects_malformed() {
        assert!(parse_expires_in("5").is_err(), "unit required");
        assert!(parse_expires_in("0d").is_err(), "positive required");
        assert!(parse_expires_in("-3h").is_err(), "positive required");
        assert!(parse_expires_in("xd").is_err(), "integer required");
    }

    #[test]
    fn load_signing_key_reads_hex_file() {
        let signing_key = SigningKey::from_seed([3u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-signing-key");
        std::fs::write(&path, hex::encode(signing_key.to_bytes())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let loaded = load_signing_key(Some(&path)).expect("signing key file must load");
        assert_eq!(
            loaded.to_bytes(),
            signing_key.to_bytes(),
            "loaded key must match the persisted seed"
        );
    }

    #[test]
    fn parse_signing_key_hex_rejects_garbage() {
        assert!(parse_signing_key_hex("").is_err(), "empty is rejected");
        assert!(
            parse_signing_key_hex("nothex").is_err(),
            "non-hex is rejected"
        );
        assert!(
            parse_signing_key_hex("ab").is_err(),
            "wrong length is rejected"
        );
    }
}
