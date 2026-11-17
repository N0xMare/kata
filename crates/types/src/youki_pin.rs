//! The rootless-OCI containment-binary pin — `config/youki-pin.toml`, parsed ONCE.
//!
//! # Why this type exists in `kata-types`
//!
//! Four surfaces make a claim about the SAME file, and they must agree about
//! which bytes at which path the exact-path AppArmor profile covers:
//!
//! | Surface | What it does with the pin |
//! |---|---|
//! | `kata host apparmor-install` | writes and loads the rendered profile from it |
//! | `scripts/feasibility-probes.py` (`probe_youki`) | refuses a binary that is not it |
//! | `kata doctor`'s `containment_runtime` / `containment_userns` / `containment_syscall_fence` rows | read its state through the certification's folds, without starting a container |
//! | [`kata_worker::oci_runtime::certify_youki`] | CERTIFIES it, and refuses by name |
//!
//! The parse cannot live in a binary, because the worker cannot depend on one,
//! and a second Rust spelling for `certify_youki` would be two readers of one
//! fact, able to disagree about it. So the parse lives here — in the neutral type crate both a
//! binary and the worker already depend on — and every reader reads THIS type.
//!
//! # It is a property of the BUILD, not of the working directory
//!
//! [`YoukiPin::embedded`] parses a string `include_str!`'d at compile time. A
//! runtime read would make every surface's answer a fact about
//! whichever directory the operator happened to run the binary from. Re-pinning
//! therefore requires a rebuild, which `config/youki-pin.toml` says in its own
//! header.
//!
//! # This module performs NO I/O
//!
//! It parses and refuses a declaration. Whether the pinned path holds the pinned
//! bytes, whether a profile is loaded, and whether a container starts are three
//! separate observations owned by `kata doctor`, `certify_youki`, and the
//! feasibility probe respectively. A parser that also looked at the disk would
//! make those surfaces unable to test their folds without a host.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::{
    error::{KataError, KataResult},
    nix_environment::StorePath,
};

/// `config/youki-pin.toml`, embedded at BUILD time. See the module docs.
const EMBEDDED_PIN_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/youki-pin.toml"
));

/// Number of characters in the pin's `sha256` field, as `sha256sum` prints it.
const SHA256_HEX_CHARACTERS: usize = 64;

/// The shipped pin file exactly as `[youki]` declares it.
///
/// `deny_unknown_fields` on BOTH levels: a key nobody reads is a claim an
/// operator believes is in force. A renamed field must red the parse rather than
/// be silently ignored while every surface keeps using the old value.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinFile {
    youki: RawPin,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPin {
    realised_by: String,
    version: String,
    store_path: String,
    sha256: String,
    profile_name: String,
    pinned_on: String,
}

/// The parsed, VALIDATED pin.
///
/// # Refused set
///
/// [`YoukiPin::parse`] accepts a document if and only if: it is TOML with
/// exactly one `[youki]` table carrying exactly the six string fields below;
/// `version` is three dot-separated decimal components (a trailing suffix such
/// as `-rc1` after the third is refused, because a floor comparison must be
/// total); `store_path` is an absolute path whose ENCLOSING store object
/// satisfies [`StorePath::new`] and which names something strictly INSIDE that
/// object; `sha256` is exactly 64 lowercase hex characters; and `profile_name`
/// is one non-empty path-free name that is neither `.` nor `..`. Everything else
/// is refused.
///
/// It says NOTHING about the host: not that the path exists, not that the bytes
/// hash to `sha256`, not that a profile is loaded. Those are observations, and
/// each has exactly one owner elsewhere.
///
/// # Fields are private on purpose
///
/// Every field is reachable through an accessor and none is publicly writable,
/// so a `YoukiPin` in hand is always one that passed the refused set above. A
/// `pub` field set would let a caller build a pin naming a path
/// [`StorePath::new`] refuses, which is precisely the state the renderer's
/// exact-path profile cannot cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YoukiPin {
    realised_by: String,
    version: String,
    version_tuple: (u64, u64, u64),
    store_path: String,
    store_object: StorePath,
    sha256: String,
    profile_name: String,
    pinned_on: String,
}

impl YoukiPin {
    /// The pin THIS BUILD embeds, parsed at most once per process.
    ///
    /// # Panics
    ///
    /// If the embedded `config/youki-pin.toml` does not parse. That is a build
    /// defect rather than a host condition — the file is compiled in, so it is
    /// identical on every host this binary runs on, and no operator action can
    /// change it. Callers that must REPORT the malformed case rather than die
    /// (`kata doctor`) use [`YoukiPin::embedded_result`].
    #[must_use]
    pub fn embedded() -> &'static YoukiPin {
        Self::embedded_result().unwrap_or_else(|error| {
            panic!("the youki pin embedded from config/youki-pin.toml does not parse: {error}")
        })
    }

    /// [`YoukiPin::embedded`] without the panic, for the one surface whose job
    /// is to report a malformed pin as a check rather than crash the process.
    pub fn embedded_result() -> Result<&'static YoukiPin, &'static KataError> {
        static PIN: OnceLock<Result<YoukiPin, KataError>> = OnceLock::new();
        PIN.get_or_init(|| YoukiPin::parse(EMBEDDED_PIN_TOML))
            .as_ref()
    }

    /// Parse and validate one pin document. See the type's refused set.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] naming the FIELD that was refused, so an
    /// operator can fix one line — the same discipline
    /// `scripts/feasibility-probes.py`'s pin loader follows, because the two
    /// read the same file and an operator will see whichever fires first.
    pub fn parse(document: &str) -> KataResult<YoukiPin> {
        let raw = toml::from_str::<PinFile>(document)
            .map_err(|error| validation(format!("the youki pin does not parse: {error}")))?
            .youki;

        let version_tuple = parse_version(&raw.version).ok_or_else(|| {
            validation(format!(
                "youki pin `version` must be three dot-separated decimal components (a floor \
                 comparison must be total), got {version:?}",
                version = raw.version
            ))
        })?;

        let store_object = enclosing_store_object(&raw.store_path)?;

        if raw.sha256.len() != SHA256_HEX_CHARACTERS
            || !raw
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(validation(format!(
                "youki pin `sha256` must be {SHA256_HEX_CHARACTERS} lowercase hex characters as \
                 `sha256sum` prints them, got {sha:?}",
                sha = raw.sha256
            )));
        }

        if raw.profile_name.contains('/')
            || matches!(raw.profile_name.as_str(), "" | "." | "..")
            || raw.profile_name.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(validation(format!(
                "youki pin `profile_name` must be one non-empty path-free name — it is joined \
                 onto /etc/apparmor.d and is the key the kernel's loaded-profile list uses — got \
                 {name:?}",
                name = raw.profile_name
            )));
        }

        Ok(YoukiPin {
            realised_by: raw.realised_by,
            version: raw.version,
            version_tuple,
            store_path: raw.store_path,
            store_object,
            sha256: raw.sha256,
            profile_name: raw.profile_name,
            pinned_on: raw.pinned_on,
        })
    }

    /// The exact COMMAND that realizes [`Self::store_path`], quoted verbatim
    /// into the remediation a surface prints when the binary is absent.
    ///
    /// A command and not a `nixpkgs#…` attribute, because the pinned runtime is
    /// not a nixpkgs attribute's output: `nixpkgs#youki` builds without
    /// `libcontainer/libseccomp` and so IGNORES `linux.seccomp`, which
    /// [`kata_worker::oci_runtime::certify_youki`] refuses. A remediation quoting
    /// that attribute would instruct an operator to install the one binary this
    /// certification exists to reject, so the field carries what actually
    /// reproduces the pinned bytes (`nix/youki.nix`, whose nixpkgs revision is
    /// pinned by hash) instead.
    #[must_use]
    pub fn realised_by(&self) -> &str {
        &self.realised_by
    }

    /// The pinned version, verbatim from the file.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The pinned version as a comparable `(major, minor, patch)` — the FLOOR a
    /// certification enforces.
    #[must_use]
    pub fn version_tuple(&self) -> (u64, u64, u64) {
        self.version_tuple
    }

    /// The exact executable AppArmor evaluates and kata will `execve`.
    #[must_use]
    pub fn store_path(&self) -> &str {
        &self.store_path
    }

    /// The store OBJECT that [`Self::store_path`] lives inside.
    ///
    /// # Why the pin is not itself a [`StorePath`]
    ///
    /// [`StorePath`] deliberately refuses an INTERIOR path: a manifest binds
    /// whole store objects, and a path into one would be a mount disagreeing
    /// with the closure it came from. The pin is the opposite kind of fact — it
    /// names the one EXECUTABLE the LSM attaches a profile to, which is
    /// necessarily `<object>/bin/youki`. So the validation reuses
    /// [`StorePath::new`] on the enclosing object (which is what proves the
    /// `/nix/store/<32 nix-base32>-<name>` shape, immutability and all) and
    /// keeps the interior remainder beside it, rather than restating half of
    /// that grammar in a second place.
    #[must_use]
    pub fn store_object(&self) -> &StorePath {
        &self.store_object
    }

    /// sha256 of the pinned file's bytes, as `sha256sum` prints it.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The AppArmor profile NAME the renderer emits and installs as
    /// `/etc/apparmor.d/<profile_name>`. The kernel's loaded-profile list is
    /// keyed by this name; the name-to-path binding lives in the rendered text
    /// alone.
    #[must_use]
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// When these fields were last established on a host.
    #[must_use]
    pub fn pinned_on(&self) -> &str {
        &self.pinned_on
    }
}

/// Validate `path` as `<store object>/<interior>` and return the object.
fn enclosing_store_object(path: &str) -> KataResult<StorePath> {
    let refuse = |reason: &str| {
        Err(validation(format!(
            "youki pin `store_path` {path:?} refused: {reason}"
        )))
    };
    let Some(base) = path.strip_prefix("/nix/store/") else {
        return refuse(
            "must be an absolute path to an executable inside one /nix/store object, so it \
             begins with /nix/store/",
        );
    };
    let Some((object, interior)) = base.split_once('/') else {
        return refuse(
            "names a whole store object rather than the executable inside it — AppArmor \
             attaches a profile to one exact executable path",
        );
    };
    if interior.is_empty() {
        return refuse("has a trailing slash and so names no executable inside the store object");
    }
    StorePath::new(format!("/nix/store/{object}"))
}

/// Three dot-separated decimal components, and nothing after them.
fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn validation(message: String) -> KataError {
    KataError::Validation(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin fields THIS BUILD embeds, pinned against literals.
    ///
    /// # Why literals
    ///
    /// A literal per field is the whole guard the embedded pin needs: a re-pin
    /// that changes the file without updating this test reds HERE, and the same
    /// edit reds the AppArmor profile golden in `kata_worker::oci_runtime`'s
    /// suite — the file the profile is compared against byte for byte.
    ///
    /// **Would red if:** anyone re-pins `config/youki-pin.toml` without
    /// re-rendering the AppArmor profile and updating both goldens.
    #[test]
    fn the_embedded_pin_parses_into_exactly_the_shipped_fields() {
        let pin = YoukiPin::embedded();
        assert_eq!(
            pin.realised_by(),
            "nix build -o .kata/youki-root -f nix/youki.nix"
        );
        assert_eq!(pin.version(), "0.7.0");
        assert_eq!(pin.version_tuple(), (0, 7, 0));
        assert_eq!(
            pin.store_path(),
            "/nix/store/dwi0lfqpz41vv8sap08c2ykdga1970nl-youki-seccomp-0.7.0/bin/youki"
        );
        assert_eq!(
            pin.store_object().as_str(),
            "/nix/store/dwi0lfqpz41vv8sap08c2ykdga1970nl-youki-seccomp-0.7.0"
        );
        assert_eq!(
            pin.sha256(),
            "599108f43913c42f383e9a32d44a54bcf2e0fcd8ae7cee647a04bf759e502f8b"
        );
        assert_eq!(pin.profile_name(), "youki");
        assert_eq!(pin.pinned_on(), "2026-11-11");
    }

    fn sample(field: &str, value: &str) -> String {
        let mut document = String::from("[youki]\n");
        for (name, shipped) in [
            (
                "realised_by",
                "nix build -o .kata/youki-root -f nix/youki.nix",
            ),
            ("version", "0.7.0"),
            (
                "store_path",
                "/nix/store/dwi0lfqpz41vv8sap08c2ykdga1970nl-youki-seccomp-0.7.0/bin/youki",
            ),
            (
                "sha256",
                "599108f43913c42f383e9a32d44a54bcf2e0fcd8ae7cee647a04bf759e502f8b",
            ),
            ("profile_name", "youki"),
            ("pinned_on", "2026-11-11"),
        ] {
            let used = if name == field { value } else { shipped };
            use std::fmt::Write as _;
            let _ = writeln!(document, "{name} = \"{used}\"");
        }
        document
    }

    /// Every clause of the refused set fires, and NAMES the field it refused.
    #[test]
    fn each_refusal_fires_and_names_its_field() {
        assert!(YoukiPin::parse(&sample("version", "0.7.0")).is_ok());
        for (field, value, expect) in [
            ("version", "0.7", "version"),
            ("version", "0.7.0-rc1", "version"),
            ("sha256", "abc", "sha256"),
            (
                "sha256",
                "545DF2CE5154CE5371737F09061E1317E90B793E28F5D18A099082E7C96A368C",
                "sha256",
            ),
            ("profile_name", "a/b", "profile_name"),
            ("profile_name", "", "profile_name"),
            ("store_path", "nix/store/x-y/bin/youki", "store_path"),
            (
                "store_path",
                "/nix/store/dwi0lfqpz41vv8sap08c2ykdga1970nl-youki-seccomp-0.7.0",
                "store_path",
            ),
            ("store_path", "/usr/bin/youki", "store_path"),
            // The digest is nix-base32: `e`, `o`, `u` and `t` are not in the
            // alphabet, and `StorePath::new` is what catches it.
            (
                "store_path",
                "/nix/store/eoutjgr48vsclxxyj2zjkj3ydzys0khc-youki-seccomp-0.7.0/bin/youki",
                "store path",
            ),
        ] {
            let error = YoukiPin::parse(&sample(field, value))
                .expect_err(&format!("{field} = {value:?} must be refused"))
                .to_string();
            assert!(
                error.contains(expect),
                "the refusal for {field} = {value:?} must name {expect:?}: {error}"
            );
        }
    }

    /// An unknown key is a REFUSAL, not a silently ignored claim.
    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let mut document = sample("version", "0.7.0");
        document.push_str("relax_userns_restriction = true\n");
        let error = YoukiPin::parse(&document)
            .expect_err("an unknown key must be refused")
            .to_string();
        assert!(
            error.contains("relax_userns_restriction"),
            "the refusal must name the unknown key: {error}"
        );
        assert!(
            YoukiPin::parse("[youki]\nversion = \"0.7.0\"\n").is_err(),
            "a table missing five of the six fields must be refused"
        );
        assert!(
            YoukiPin::parse("[oci]\n").is_err(),
            "a document with no [youki] table must be refused"
        );
    }
}
