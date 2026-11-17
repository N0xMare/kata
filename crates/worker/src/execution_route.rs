//! The external-provider DECLARATION channel, and the OCI route value.
//!
//! # What this module is now
//!
//! Two things, and the two are related by the capsule route:
//!
//! * the node-configuration channel a node uses to declare its external
//!   provider — [`EXTERNAL_PROVIDER_ENV`] names WHICH provider and
//!   [`EXTERNAL_PROVIDER_ADDRESS_ENV`] names WHICH BYTES, resolved through the
//!   by-hash [`crate::provider_store`]. [`declared_external_provider`] is the
//!   one reader of both keys; [`crate::capsule_route::CapsuleRoute::admit`]
//!   calls it and refuses `oci_provider_undeclared` when it answers `None`.
//! * [`OciRoute`] — the admitted rootless-OCI route, an owned clone of the one
//!   [`crate::oci_runtime::certified_oci_route`] measurement plus the
//!   [`OciMeasuredBasis`] the provider's certificate is compared against.
//!
//! # There is no route decision
//!
//! The capsule route is the only execution path, so nothing here chooses
//! between a linked runtime and an external provider. What this module holds
//! is the DECLARATION: the capsule route admits its provider through exactly
//! this channel.
//!
//! A **provider** is an external process kata does NOT link — it receives work
//! over the versioned `kata-provider-protocol`. There is deliberately no
//! generic route enum: adding a second route is a design decision, not a
//! variant.

use kata_provider_protocol::OciMeasuredBasis;
use kata_types::error::{KataError, KataResult};
use kata_types::sandbox::{ExecBackend, ExecProviderPosture};

use crate::oci_runtime::YoukiCertification;

/// The node-configuration channel that names this node's external provider.
///
/// # Why this spelling
///
/// `KATA_EXECUTION_PROVIDER` was rejected: `kata execution-provider list`
/// already enumerates the containment backends, so that name would make one
/// string mean both "which containment runtime" and "which unlinked process" —
/// the ambiguous-name defect, minted at the exact place the vocabulary is most
/// load-bearing. `EXTERNAL` is the word kata uses for such a process throughout.
///
/// UNSET means this node declares no provider — and since the capsule route
/// admits its provider through this declaration, an undeclared node cannot run
/// capsule stages at all: [`crate::capsule_route::CapsuleRoute::admit`] refuses
/// `oci_provider_undeclared` there rather than guessing. A blank value is
/// ABSENT — an exported-but-empty variable is a node that never declared a
/// provider, not a node that declared one called `""` — the same reading
/// [`crate::provider_store::declared_provider_store_root`] gives its own key.
pub const EXTERNAL_PROVIDER_ENV: &str = "KATA_EXTERNAL_EXECUTION_PROVIDER";

/// The node-configuration channel carrying the provider's CONTENT ADDRESS.
///
/// # Why a SECOND value and not the first one repurposed
///
/// **The declared value stays a NAME, and the address rides beside it.** Three
/// reasons, and none of them is taste.
///
/// 1. `ProviderCertificate::provider` is compared against the declared NAME at
///    the handshake (`kata_provider_protocol::admit`), and that check is
///    meaningful: it is the provider's own claim about which provider it is,
///    checked against what the operator asked for. Collapsing name into address
///    would conflate identity-of-KIND with identity-of-BYTES and lose the
///    ability to say *"this is the youki provider"* separately from *"these are
///    the bytes"*.
/// 2. Temporal's Build ID is exactly this shape — a version field SEPARATE from
///    the task-queue name — for the same reason: the queue is what work is
///    addressed to, the build id is which code answers.
/// 3. It leaves [`ExternalProviderDeclaration::parse_name`]'s charset untouched,
///    so the containment-backend-name refusal survives unchanged.
///
/// **Reversing costs**: this constant, [`ExternalProviderAddress`], and the
/// two-argument shape of [`ExternalProviderDeclaration::parse`]. The handshake
/// comparison and `docs/architecture/0001-replacement-architecture.md`'s
/// certificate table would then have to say what a name-that-is-an-address is
/// compared against, which is the question this answer avoids having to ask.
///
/// **The trap this closes.** The name parser refuses `:` so `store:<hex>`
/// cannot be typed into [`EXTERNAL_PROVIDER_ENV`] — but a BARE 64-character
/// blake3 hex would pass its charset check, so routing an address through the
/// NAME field would silently work. [`ExternalProviderDeclaration::parse_name`]
/// refuses exactly that shape by name, so the confusion is unrepresentable
/// rather than merely unused.
pub const EXTERNAL_PROVIDER_ADDRESS_ENV: &str = "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS";

/// The CONTENT ADDRESS of an external provider's store entry.
///
/// Rendered `store:<64 lowercase hex>` and parsed from exactly that. A bare hex
/// is REFUSED: there is exactly one basis a provider address can have — kata
/// copied the bytes into a store it owns and re-derives their hash before
/// spawning them.
///
/// A separate type from
/// [`ToolchainRequirement`](kata_types::sandbox::ToolchainRequirement) on
/// purpose: a toolchain requirement and a provider address are different KINDS,
/// and one type for both is the ambiguous-name defect at the point where a wrong
/// lookup would spawn the wrong process.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalProviderAddress {
    hex: String,
}

impl ExternalProviderAddress {
    /// The `store:` prefix a provider address carries, shared with the toolchain
    /// store's spelling so an operator meets one vocabulary for one idea.
    pub const PREFIX: &'static str = kata_types::sandbox::STORE_BASIS_PREFIX;

    /// The bare blake3 hex, WITHOUT the prefix — the store entry's directory
    /// name on whichever node resolves this.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Mint an address from a hex a store has ALREADY verified.
    ///
    /// `pub(crate)`-shaped intent, `pub` reach: `crate::provider_store` is the
    /// only caller and it passes the value `verify_store_entry` computed from
    /// the entry's own bytes. It takes no `Result` because there is nothing left
    /// to check — a hex that came out of `blake3::Hash::to_hex` is 64 lowercase
    /// hex characters by construction.
    #[must_use]
    pub fn from_verified_hex(hex: &str) -> Self {
        Self {
            hex: hex.to_owned(),
        }
    }

    /// Parse an operator-declared address, or say why it is not one.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] naming the key and the exact shape. Never a
    /// fallback and never a guess: an address kata cannot interpret must not be
    /// treated as "no address", because that would silently declare no provider
    /// — and the capsule route would then refuse this node
    /// `oci_provider_undeclared` for a reason the operator did not write.
    pub fn parse(raw: &str) -> KataResult<Self> {
        let raw = raw.trim();
        let hex = raw.strip_prefix(Self::PREFIX).unwrap_or_default();
        if !kata_types::sandbox::is_blake3_hex(hex) {
            return Err(KataError::Validation(format!(
                "sandbox: `{EXTERNAL_PROVIDER_ADDRESS_ENV}={raw}` is not a provider content \
                 address. A provider address is `{prefix}` followed by the 64 lowercase hex \
                 characters of a by-hash provider-store entry — the value `kata sandbox \
                 install-external-provider` prints. It is never a filesystem PATH: a path names \
                 whatever bytes currently sit there, which is identification by location, and \
                 it would only resolve on the host that wrote it.",
                prefix = Self::PREFIX,
            )));
        }
        Ok(Self {
            hex: hex.to_owned(),
        })
    }
}

impl std::fmt::Display for ExternalProviderAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", Self::PREFIX, self.hex)
    }
}

/// An operator's declaration of the external provider this node routes to: a
/// validated NAME **and** the CONTENT ADDRESS of its bytes.
///
/// Neither is a path, and that is structural rather than discouraged — the name
/// admits no `/` (it admits no `:` either) and the address admits only
/// `store:<hex>`. So there is no string either field can hold that names a
/// location.
///
/// Constructed only by [`Self::parse`], so a value of this type is a declaration
/// that passed every shape check — including the one that refuses a containment
/// backend's own spelling and the one that refuses an ADDRESS wearing the name
/// field's clothes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalProviderDeclaration {
    name: String,
    address: ExternalProviderAddress,
}

impl ExternalProviderDeclaration {
    /// The provider's declared name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The content address of the provider's bytes, exactly as declared.
    #[must_use]
    pub const fn address(&self) -> &ExternalProviderAddress {
        &self.address
    }

    /// Validate a declared provider NAME, or say why it is not one.
    ///
    /// The charset is ASCII lowercase, digits, `-` and `_`, on purpose: it is
    /// the charset the by-hash store derives `kata-provider-<name>` directory
    /// names from, and it admits no `:` so `store:<hex>` cannot be typed here.
    /// Two further refusals keep the two declaration fields unswappable:
    /// a bare blake3 hex is an address in the name field's clothes, and a
    /// containment backend's authored spelling is a KIND of thing a provider is
    /// not — a declaration named `host` would have kata look for
    /// `kata-provider-host` and say only that it was missing, a true sentence
    /// about the wrong mistake.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] naming the key and what a valid value looks
    /// like. Never a fallback: an unparseable declaration is an operator who
    /// asked for something, and answering them with no provider would leave the
    /// capsule route refusing this node for a reason they never wrote.
    pub fn parse_name(raw: &str) -> KataResult<String> {
        let name = raw.trim();
        if name.is_empty() {
            return Err(KataError::Validation(format!(
                "sandbox: `{EXTERNAL_PROVIDER_ENV}` is set to a blank value. Unset it to declare \
                 no provider (the capsule route then refuses OCI work on this node), or name the \
                 external provider this node routes to."
            )));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return Err(KataError::Validation(format!(
                "sandbox: `{EXTERNAL_PROVIDER_ENV}={name}` is not a provider NAME. Valid \
                 characters are ASCII lowercase, digits, `-` and `_`. This key names WHICH \
                 external provider this node routes to; WHERE its bytes are is \
                 `{EXTERNAL_PROVIDER_ADDRESS_ENV}`, a content address with a store lookup behind \
                 it, and neither key is ever a path."
            )));
        }
        if kata_types::sandbox::is_blake3_hex(name) {
            return Err(KataError::Validation(format!(
                "sandbox: `{EXTERNAL_PROVIDER_ENV}={name}` is a 64-character blake3 hex, which is \
                 a provider ADDRESS and not a provider NAME. Addresses go in \
                 `{EXTERNAL_PROVIDER_ADDRESS_ENV}`, spelled `store:{name}`. The two keys are \
                 refused for each other rather than accepted-and-failed-later: a name that is \
                 secretly an address would have kata looking for an executable called \
                 `kata-provider-{name}` and reporting only that it was missing, which is a true \
                 sentence about the wrong mistake."
            )));
        }
        if let Some(linked) = ExecBackend::all().find(|b| b.authored_spelling() == name) {
            return Err(KataError::Validation(format!(
                "sandbox: `{EXTERNAL_PROVIDER_ENV}={name}` names `{name}`, which is already the \
                 authored spelling of a containment backend (posture {posture}). An EXTERNAL \
                 provider is a different KIND of thing from a containment runtime — kata does \
                 not link it and has not measured its containment — so it may not wear a \
                 backend's name. Give the provider its own name.",
                posture = posture_label(linked.provider_posture()),
            )));
        }
        Ok(name.to_string())
    }

    /// Parse both node-configuration values into one declaration.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::parse_name`] or [`ExternalProviderAddress::parse`]
    /// refuses.
    pub fn parse(name: &str, address: &str) -> KataResult<Self> {
        Ok(Self {
            name: Self::parse_name(name)?,
            address: ExternalProviderAddress::parse(address)?,
        })
    }
}

/// THIS NODE's declared external provider, or `None`.
///
/// The ONE reader of [`EXTERNAL_PROVIDER_ENV`] and
/// [`EXTERNAL_PROVIDER_ADDRESS_ENV`], so the capsule route's admission and the
/// lever report cannot disagree about whether this node declared one.
///
/// # Both keys or neither — and a half-declaration is a REFUSAL
///
/// `None` means *this operator declared nothing*, and the capsule route refuses
/// this node `oci_provider_undeclared` for exactly that. An operator who set ONE
/// of the two keys declared something, and answering them with no provider
/// would report the wrong mistake — including in the direction that looks
/// harmless: a node with an ADDRESS and no NAME has said which bytes it wants
/// and would otherwise get an undeclared-provider refusal that never mentions
/// the missing half.
///
/// # Errors
///
/// Propagates [`ExternalProviderDeclaration::parse`]'s refusals, plus the two
/// half-declaration refusals above.
pub fn declared_external_provider() -> KataResult<Option<ExternalProviderDeclaration>> {
    let name = declared_text(EXTERNAL_PROVIDER_ENV)?;
    let address = declared_text(EXTERNAL_PROVIDER_ADDRESS_ENV)?;
    match (name, address) {
        (None, None) => Ok(None),
        (Some(name), Some(address)) => {
            ExternalProviderDeclaration::parse(&name, &address).map(Some)
        }
        (Some(name), None) => Err(KataError::Validation(format!(
            "sandbox: this node declares the EXTERNAL provider `{name}` \
             (`{EXTERNAL_PROVIDER_ENV}`) and no `{EXTERNAL_PROVIDER_ADDRESS_ENV}`. A provider \
             is identified by CONTENT: the name says WHICH provider and the address says \
             which BYTES, and kata resolves the address through this node's by-hash provider \
             store. It does not search `PATH`, because `PATH` is the environment of whatever \
             process the worker happens to be and so answers differently on the same node. \
             Install the provider with `kata sandbox \
             install-external-provider --name {name} <directory>` and export the address it \
             prints, or unset `{EXTERNAL_PROVIDER_ENV}` to declare no provider."
        ))),
        (None, Some(address)) => Err(KataError::Validation(format!(
            "sandbox: this node declares the provider address \
             `{EXTERNAL_PROVIDER_ADDRESS_ENV}={address}` and no `{EXTERNAL_PROVIDER_ENV}`, so it \
             has named bytes without naming a provider. The address picks a store ENTRY and the \
             name picks the executable inside it, so neither alone resolves to a binary. Refusing \
             rather than reporting this node as undeclared: an operator who wrote an address \
             asked for a provider, and an `oci_provider_undeclared` that never mentioned the \
             missing name would send them fixing the wrong half."
        ))),
    }
}

/// Did this node declare a provider ADDRESS at all?
///
/// PRESENCE only, and it deliberately does not parse: the
/// [`ContainmentLever`](crate::sandbox_posture::ContainmentLever) surface's own
/// rule is that a MALFORMED declaration reports as SET, because the operator
/// declared something and every stage on this node is about to be refused by
/// name because of it. Read through the same [`non_blank`] rule
/// [`declared_external_provider`] uses, so the lever report and the route
/// admission cannot disagree about whether the key is set.
#[must_use]
pub fn external_provider_address_declared() -> bool {
    declared_text(EXTERNAL_PROVIDER_ADDRESS_ENV).map_or(true, |address| address.is_some())
}

/// One node-configuration variable's value, treating unset and blank alike —
/// the present-and-non-blank rule every provider key is read by (this module's
/// two and `crate::provider_store::declared_provider_store_root`'s), so an
/// exported-but-empty variable means the same thing at every door.
///
/// # Errors
///
/// Exactly a value that is not UTF-8: refused naming `key`, never the value.
/// Read as unset, it would earn an `oci_provider_undeclared` (or a
/// half-declaration refusal) that sends the operator after the wrong mistake.
pub(crate) fn declared_text(key: &str) -> KataResult<Option<String>> {
    let Some(raw) = std::env::var_os(key) else {
        return Ok(None);
    };
    let raw = raw.into_string().map_err(|_| {
        KataError::Validation(format!(
            "sandbox: `{key}` is set to a value that is not UTF-8. kata reads this node's \
             provider declaration as text and cannot read this one; re-export `{key}` as \
             UTF-8, or unset it to declare nothing"
        ))
    })?;
    let raw = raw.trim();
    Ok((!raw.is_empty()).then(|| raw.to_owned()))
}

/// The stable posture token, quoted from the ONE authority's variant rather than
/// re-worded per site.
const fn posture_label(posture: ExecProviderPosture) -> &'static str {
    match posture {
        ExecProviderPosture::CertifiedContainment => "certified_containment",
        ExecProviderPosture::Unconfined => "unconfined",
        ExecProviderPosture::UnsupportedInThisBuild => "unsupported_in_this_build",
    }
}

/// An ADMITTED rootless-OCI route: a capsule runs
/// inside a container kata PLANNED, under a runtime kata PINNED and CERTIFIED.
///
/// The one holder is [`crate::oci_driver::OciStageDriver`], admitted by
/// [`crate::capsule_route::CapsuleRoute`] on an `oci`-profile worker.
///
/// # What kata has measured on this route
///
/// Kata derived the whole `config.json` (`crate::oci_bundle::spec_for`), pinned
/// and re-digested the runtime, read its AppArmor profile and its libseccomp
/// support out of the binary, and owns the cgroup the container lives in — and
/// the provider that starts it can only ECHO that measurement, because
/// [`kata_provider_protocol::admit`] compares its certificate against
/// [`Self::measured_basis`] field by field.
///
/// # The certification is CARRIED, never re-derived
///
/// `certify_youki` FORKS A CONTAINER and its `functional_probe_id` names that
/// one container. A consumer that re-certified would hold a different
/// measurement from the one this route was admitted on, and the basis a
/// provider is held to restate would name a probe that is not the probe kata
/// ran. [`crate::oci_runtime::certified_oci_route`] is the one measurement per
/// process; this type holds an owned CLONE of it, never a second measurement.
#[derive(Clone, Debug)]
pub struct OciRoute {
    certification: YoukiCertification,
    basis: OciMeasuredBasis,
}

impl OciRoute {
    /// Admit a route on a certification, folding the measured basis from it.
    ///
    /// The basis is DERIVED here and cannot be passed, which is the point: it is
    /// [`crate::provider_supervisor::measured_basis_from_certification`]'s output
    /// and that function is the workspace's only producer, so a route cannot exist
    /// carrying a basis that is not a fold of its own certification. That pairing
    /// is what [`kata_provider_protocol::admit`]'s equality is comparing a
    /// provider's certificate against.
    #[must_use]
    pub fn new(certification: YoukiCertification) -> Self {
        Self {
            basis: crate::provider_supervisor::measured_basis_from_certification(&certification),
            certification,
        }
    }

    /// What `certify_youki` measured on this host — the pinned path, its sha256,
    /// the version pair, the libseccomp witness, the installed profile digest,
    /// the userns restriction, the delegation and the functional probe's id.
    #[must_use]
    pub const fn certification(&self) -> &YoukiCertification {
        &self.certification
    }

    /// The same measurement as the provider's certificate must restate it.
    ///
    /// Folded ONCE, by [`crate::provider_supervisor::measured_basis_from_certification`]
    /// — the workspace's only producer — and carried rather than folded per use,
    /// so *"what kata measured"* has one spelling on both sides of
    /// [`kata_provider_protocol::admit`]'s equality.
    #[must_use]
    pub const fn measured_basis(&self) -> &OciMeasuredBasis {
        &self.basis
    }

    /// One line naming this route, for a log or a message that has to say where
    /// a stage went.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "this node's capsule route is the rootless-OCI runtime its `oci` execution profile \
             requires, CERTIFIED on this host: youki \
             {major}.{minor}.{patch} at {path} (sha256 {sha}), libseccomp {libseccomp}, AppArmor \
             {profile}, userns restriction {userns}, functional probe {probe}",
            major = self.certification.version.0,
            minor = self.certification.version.1,
            patch = self.certification.version.2,
            path = self.certification.store_path.display(),
            sha = self.certification.sha256,
            libseccomp = self.certification.libseccomp_version,
            profile = self.certification.profile.label(),
            userns = self.certification.userns_restriction.label(),
            probe = self.certification.functional_probe_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;

    use super::{EXTERNAL_PROVIDER_ADDRESS_ENV, EXTERNAL_PROVIDER_ENV};
    use crate::provider_store::EXTERNAL_PROVIDER_STORE_ENV;

    /// Set in the child run: the cell prints each reader's answer.
    const CHILD: &str = "KATA_NON_UTF8_PROVIDER_CHILD";

    /// **A node-provider variable that is not UTF-8 is refused naming it, never
    /// read as unset.** For each of the three keys (`KATA_EXTERNAL_PROVIDER_STORE`,
    /// `KATA_EXTERNAL_EXECUTION_PROVIDER`, `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS`),
    /// a child of this test binary (the workspace denies `unsafe_code`, so the
    /// cell cannot `set_var`) holds that key set to bytes that are not UTF-8 and
    /// the other two set validly: the key's reader refuses naming the variable as
    /// not UTF-8 (the store root's for the store, `declared_external_provider` for
    /// the name and the address), the lever report reads an unreadable address as
    /// SET, and neither of the child's streams carries the planted bytes.
    ///
    /// **Would red if:** a reader took a non-UTF-8 value for an unset one
    /// (watched, the readers before this cell: the store root `None`, a
    /// half-declaration refusal for the name, `oci_provider_undeclared` for both
    /// keys unread).
    #[test]
    fn a_non_utf8_provider_variable_is_refused_naming_it() {
        if std::env::var_os(CHILD).is_some() {
            println!(
                "provider: {:?}",
                super::declared_external_provider().map(|declared| declared.is_some())
            );
            println!(
                "store: {:?}",
                crate::provider_store::declared_provider_store_root()
            );
            println!(
                "address_set: {}",
                super::external_provider_address_declared()
            );
            return;
        }
        let valid = [
            (
                EXTERNAL_PROVIDER_STORE_ENV,
                "/srv/kata-u23/providers".to_owned(),
            ),
            (EXTERNAL_PROVIDER_ENV, "youki".to_owned()),
            (
                EXTERNAL_PROVIDER_ADDRESS_ENV,
                format!("store:{}", "a".repeat(64)),
            ),
        ];
        for (planted, line) in [
            (EXTERNAL_PROVIDER_STORE_ENV, "store: "),
            (EXTERNAL_PROVIDER_ENV, "provider: "),
            (EXTERNAL_PROVIDER_ADDRESS_ENV, "provider: "),
        ] {
            let mut child = std::process::Command::new(
                std::env::current_exe().expect("the test binary's own path"),
            );
            child
                .args([
                    "--exact",
                    "execution_route::tests::a_non_utf8_provider_variable_is_refused_naming_it",
                    "--nocapture",
                    "--test-threads",
                    "1",
                ])
                .env(CHILD, "1");
            for (key, value) in &valid {
                if *key == planted {
                    child.env(key, std::ffi::OsStr::from_bytes(b"u23-PLANTED\xff"));
                } else {
                    child.env(key, value);
                }
            }
            let output = child.output().expect("the child run spawns");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "{planted}: the child ran the cell ({:?}):\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            for bytes in [&output.stdout, &output.stderr] {
                assert!(
                    !bytes.windows(7).any(|window| window == b"PLANTED"),
                    "{planted}: the child's output holds the planted value"
                );
            }
            let answer = stdout
                .lines()
                .find(|printed| printed.contains(line))
                .unwrap_or_else(|| panic!("{planted}: the child printed {line:?}:\n{stdout}"));
            assert!(
                answer.contains(&format!("`{planted}` is set to a value that is not UTF-8")),
                "{planted}: refused by name as not UTF-8: {answer}"
            );
            if planted == EXTERNAL_PROVIDER_ADDRESS_ENV {
                assert!(
                    stdout.contains("address_set: true"),
                    "an unreadable address is SET on the lever report:\n{stdout}"
                );
            }
        }
    }
}
