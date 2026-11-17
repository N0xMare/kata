//! The external-provider DECLARATION channel: the two node-configuration keys a
//! node uses to name its external provider, and the refusals that keep the two
//! fields unswappable.
//!
//! # What is proven here
//!
//! The channel the capsule route admits through: `declared_external_provider`
//! reads `KATA_EXTERNAL_EXECUTION_PROVIDER` and
//! `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` as ONE declaration — a name that
//! is not a backend's, an address that is `store:<hex>`, both or neither. A
//! half-declaration is a refusal rather than a `None`, and a malformed half is
//! refused BY NAME rather than reported as undeclared.
//!
//! There is no route decision to prove: the capsule route is the only
//! execution path, and `CapsuleRoute::admit` consumes this declaration
//! directly.
//!
//! # Host-independent, and rides `just gate`
//!
//! Parsing and env reading assert nothing a host has to supply, so nothing here
//! is capability-conditional and `gate_exclusion.rs`'s containment-lane coverage
//! check has no claim on it.
//!
//! An INTEGRATION test rather than an inline module because
//! `std::env::set_var` is `unsafe` under edition 2024 and `kata-worker` keeps
//! its `unsafe` to `process.rs`'s spawn-time kernel calls (see its `lib.rs`).
//! nextest runs each `#[test]` in its own process, so the toggling here cannot
//! race a sibling.

#![allow(unsafe_code)]

use kata_types::sandbox::ExecBackend;
use kata_worker::execution_route::{
    EXTERNAL_PROVIDER_ENV, ExternalProviderDeclaration, declared_external_provider,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A 64-character blake3 hex standing in for one a provider store minted.
///
/// Distinct per digit so two fixture addresses in one test are visibly
/// different.
fn fixture_hex(digit: char) -> String {
    std::iter::repeat_n(digit, 64).collect()
}

fn fixture_address(digit: char) -> String {
    format!("store:{}", fixture_hex(digit))
}

fn declaration(name: &str) -> ExternalProviderDeclaration {
    ExternalProviderDeclaration::parse(name, &fixture_address('a'))
        .expect("fixture declaration must parse")
}

/// Sets or clears a variable for the life of the guard, restoring what was
/// there.
struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    fn cleared(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

// ---------------------------------------------------------------------------
// The name refuses every containment backend's spelling
// ---------------------------------------------------------------------------

/// A provider may not wear a containment backend's name: a declaration named
/// `host` (or any authored spelling) would have kata look for
/// `kata-provider-host` and report only that it was missing — one refusal
/// string — one whose containment kata certifies, one kata has not measured
/// at all.
#[test]
fn a_declaration_may_not_wear_a_containment_backends_name() {
    let mut refused = 0;
    for backend in ExecBackend::all() {
        let err =
            ExternalProviderDeclaration::parse(backend.authored_spelling(), &fixture_address('a'))
                .expect_err("a containment backend's spelling is not an external provider name");
        assert!(
            err.to_string().contains(backend.authored_spelling()),
            "the refusal must name the spelling it refused: {err}"
        );
        refused += 1;
    }
    assert_eq!(
        refused,
        ExecBackend::all().count(),
        "non-vacuity: every backend in the closed world must be refused as a \
         provider name, and the world must not be empty"
    );
    // The control: a name that is NOT a backend spelling parses.
    assert_eq!(declaration("acme-provider").name(), "acme-provider");
}

/// A malformed declaration is a refusal, never a silent "no provider".
#[test]
fn a_malformed_declaration_is_refused_by_name_rather_than_ignored() {
    for bad in [
        "/usr/libexec/acme",
        "Acme",
        "acme provider",
        "acme.provider",
        "  ",
    ] {
        let err = ExternalProviderDeclaration::parse(bad, &fixture_address('a'))
            .expect_err("a value that is not a provider NAME must be refused");
        assert!(
            err.to_string().contains(EXTERNAL_PROVIDER_ENV),
            "every refusal must name the key an operator would edit: {err}"
        );
    }
    // The control, in the same test: the shape check refuses shapes, not
    // everything. Without it a `parse` that returned `Err` unconditionally
    // would pass the loop above.
    assert_eq!(declaration("acme_provider-2").name(), "acme_provider-2");
}

// ---------------------------------------------------------------------------
// The NAME and the ADDRESS may not be swapped
// ---------------------------------------------------------------------------

/// **The name/address swap trap, closed.**
///
/// The name parser refuses `:`, so `store:<hex>` cannot be typed into the NAME
/// key. A BARE 64-character blake3 hex is a different matter: every hex digit is
/// an ASCII lowercase letter or a digit, so it passes the charset check
/// untouched. Without the fourth refusal an operator who put the address in the
/// name key would have had kata look for an executable called
/// `kata-provider-<64 hex>` and report only that it was missing — a true
/// sentence about the wrong mistake.
///
/// **Would RED if:** `parse_name`'s `is_blake3_hex` guard were removed. Measured
/// by deleting it: the assertion below then reports
/// `Ok("aaaa…")` where a refusal is required.
#[test]
fn a_bare_blake3_hex_is_refused_as_a_provider_name() {
    let hex = fixture_hex('a');
    // PRECONDITION, or this test measures nothing: the value must pass every
    // OTHER shape check, so the refusal below can only come from the new one.
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "premise: a blake3 hex is inside the name charset, which is why it needed refusing"
    );
    let err = ExternalProviderDeclaration::parse_name(&hex)
        .expect_err("an address in the NAME key must be unrepresentable, not merely unused");
    let text = err.to_string();
    for needle in [
        EXTERNAL_PROVIDER_ENV,
        kata_worker::EXTERNAL_PROVIDER_ADDRESS_ENV,
        "store:",
    ] {
        assert!(
            text.contains(needle),
            "the refusal must send the operator to the key that DOES take an address, \
             naming {needle}: {text}"
        );
    }
}

/// And the mirror: a provider NAME is not an address.
///
/// Without this the pair above is satisfiable by an address parser that accepted
/// everything, so the two keys would be refused for each other in one direction
/// only.
#[test]
fn a_provider_name_is_refused_as_a_provider_address() {
    let err = kata_worker::ExternalProviderAddress::parse("acme-provider")
        .expect_err("a NAME is not a content address");
    assert!(
        err.to_string()
            .contains(kata_worker::EXTERNAL_PROVIDER_ADDRESS_ENV),
        "got: {err}"
    );
    // A bare hex is refused too — the strong basis must be SPELLED, never
    // acquired by writing 64 characters, which is `ToolchainRequirement::parse`'s
    // own asymmetry applied to a key with no history of bare values.
    kata_worker::ExternalProviderAddress::parse(&fixture_hex('b'))
        .expect_err("a bare hex must not silently mean `store:`");
    // A PATH is refused, which is identification by content in one assertion.
    kata_worker::ExternalProviderAddress::parse("/usr/libexec/kata-provider-acme")
        .expect_err("identification by LOCATION is refused, not merely un-chosen");
    // The control: the value `kata sandbox install-external-provider` prints
    // parses, and round-trips.
    let address = kata_worker::ExternalProviderAddress::parse(&fixture_address('c'))
        .expect("a minted address parses");
    assert_eq!(address.to_string(), fixture_address('c'));
    assert_eq!(address.hex(), fixture_hex('c'));
}

// ---------------------------------------------------------------------------
// The env channel — both keys or neither, a half-declaration refused
// ---------------------------------------------------------------------------

/// A node that declared HALF the pair is REFUSED, in both directions.
///
/// The address-without-name direction is the one worth having: it looks
/// harmless, and answering it with `oci_provider_undeclared` would send the
/// operator fixing the wrong half of their declaration.
///
/// **Would RED if:** `declared_external_provider` folded either half into
/// `Ok(None)`.
#[test]
fn a_half_declaration_is_refused_in_both_directions() {
    {
        let _name = EnvGuard::set(EXTERNAL_PROVIDER_ENV, "acme-provider");
        let _address = EnvGuard::cleared(kata_worker::EXTERNAL_PROVIDER_ADDRESS_ENV);
        let err = declared_external_provider()
            .expect_err("a name with no address resolves to no bytes and must refuse");
        assert!(
            err.to_string()
                .contains(kata_worker::EXTERNAL_PROVIDER_ADDRESS_ENV),
            "the refusal must name the key that is missing: {err}"
        );
    }
    {
        let _name = EnvGuard::cleared(EXTERNAL_PROVIDER_ENV);
        let _address = EnvGuard::set(
            kata_worker::EXTERNAL_PROVIDER_ADDRESS_ENV,
            &fixture_address('a'),
        );
        let err = declared_external_provider()
            .expect_err("an address with no name picks an entry and no executable inside it");
        assert!(
            err.to_string().contains(EXTERNAL_PROVIDER_ENV),
            "the refusal must name the key that is missing: {err}"
        );
    }
    // The control: BOTH set is a declaration, and neither refusal fires.
    {
        let _name = EnvGuard::set(EXTERNAL_PROVIDER_ENV, "acme-provider");
        let _address = EnvGuard::set(
            kata_worker::EXTERNAL_PROVIDER_ADDRESS_ENV,
            &fixture_address('a'),
        );
        let declared = declared_external_provider()
            .expect("both halves present is a well-formed declaration")
            .expect("and it is a declaration, not an absence");
        assert_eq!(declared.name(), "acme-provider");
        assert_eq!(declared.address().to_string(), fixture_address('a'));
    }
}

/// An undeclared node answers `None` — the absence `CapsuleRoute::admit`
/// refuses `oci_provider_undeclared` on.
#[test]
fn an_undeclared_node_declares_no_provider() {
    let _guard = EnvGuard::cleared(EXTERNAL_PROVIDER_ENV);
    assert!(
        declared_external_provider()
            .expect("an absent variable is not an error")
            .is_none()
    );
}

/// A blank value is ABSENT, not a provider called `""`.
#[test]
fn a_blank_declaration_is_absent_rather_than_a_provider_named_nothing() {
    let _guard = EnvGuard::set(EXTERNAL_PROVIDER_ENV, "   ");
    assert!(
        declared_external_provider()
            .expect("a blank value is not a malformed declaration")
            .is_none()
    );
}
