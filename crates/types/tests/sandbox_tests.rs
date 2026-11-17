//! Tests for `crates/types/src/sandbox.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::sandbox::{
    ExecBackend, FsPolicy, MountSpec, NetPolicy, SandboxDirective, SandboxImage, SandboxProfile,
    SandboxRef, SecretRef, ToolchainRequirement,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---- enum round-trips (JSON) ----

use kata_types::test_support::json_roundtrip;

/// The confined backend is spelled `oci`. Any other spelling is REFUSED at
/// decode, naming the token, and nothing aliases onto a live backend.
///
/// REFUSES exactly: an `ExecBackend` whose `kind` is anything but `host`/`oci`.
#[test]
fn an_unknown_backend_spelling_is_refused_by_name_never_aliased() {
    assert_eq!(
        serde_json::to_value(ExecBackend::Oci).expect("encodes"),
        serde_json::json!({"kind": "oci"}),
        "the confined backend's wire spelling is `oci`"
    );
    for unknown in ["docker", "vm"] {
        let err = serde_json::from_value::<ExecBackend>(serde_json::json!({"kind": unknown}))
            .expect_err("an unknown backend spelling must not decode")
            .to_string();
        assert!(
            err.contains(unknown) && err.contains("oci"),
            "the refusal must name `{unknown}` and the live spelling `oci`: {err}"
        );
    }
    let spellings: Vec<&str> = ExecBackend::all()
        .map(|b| ExecBackend::authored_spelling(&b))
        .collect();
    assert_eq!(
        spellings,
        vec!["host", "oci"],
        "the closed world of backends"
    );
}

#[test]
fn exec_backend_serde_roundtrip() {
    // Placement onto a subordinate worker is chosen after checking semantic
    // requirements, never authored: there is no remote variant, only the two
    // CONTAINMENT providers.
    for v in [ExecBackend::Host, ExecBackend::Oci] {
        json_roundtrip(v);
    }
}

#[test]
fn fs_policy_serde_roundtrip() {
    for v in [
        FsPolicy::Host,
        FsPolicy::WorkspaceRo,
        FsPolicy::WorkspaceRw,
        FsPolicy::Scratch,
        FsPolicy::Custom {
            mounts: vec![MountSpec {
                host_path: PathBuf::from("/tmp/src"),
                mount_point: PathBuf::from("/work"),
                writable: true,
            }],
        },
    ] {
        json_roundtrip(v);
    }
}

#[test]
fn net_policy_serde_roundtrip() {
    for v in [NetPolicy::Host, NetPolicy::Offline] {
        json_roundtrip(v);
    }
}

#[test]
fn secret_ref_serde_roundtrip() {
    json_roundtrip(SecretRef::Env("KATA_CARGO_TOKEN".into()));
    json_roundtrip(SecretRef::File(PathBuf::from("/var/run/secrets/gh")));
}

#[test]
fn sandbox_ref_serde_roundtrip() {
    json_roundtrip(SandboxRef::Named("builder".into()));
    let inline = SandboxRef::Inline(Box::new(SandboxProfile {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRo,
        net: NetPolicy::Offline,
        secrets: BTreeMap::new(),
        locked: false,
        image: None,
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    }));
    json_roundtrip(inline);
}

#[test]
fn sandbox_profile_full_roundtrip() {
    let mut secrets = BTreeMap::new();
    secrets.insert(
        "CARGO_TOKEN".to_string(),
        SecretRef::Env("KATA_CARGO_TOKEN".into()),
    );
    let profile = SandboxProfile {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRw,
        net: NetPolicy::Offline,
        secrets,
        locked: true,
        image: Some(SandboxImage {
            reference: "kata/rust-1.85:latest".into(),
            cpus: Some(4),
            memory_mb: Some(4096),
        }),
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    };
    json_roundtrip(profile);
}

#[test]
fn an_unknown_net_policy_kind_does_not_decode_as_current_authority() {
    let raw = serde_json::json!({
        "kind": "allowlist_proxy",
        "data": {"profile": "crates"}
    });
    let error = serde_json::from_value::<NetPolicy>(raw).expect_err("an unknown policy must fail");
    assert!(error.to_string().contains("unknown variant"));
}

#[test]
fn sandbox_directive_roundtrip() {
    let mut env = BTreeMap::new();
    env.insert("HTTPS_PROXY".into(), "http://127.0.0.1:3128".into());
    let mut tokens = BTreeMap::new();
    tokens.insert(
        "CARGO_TOKEN".into(),
        SecretRef::Env("KATA_CARGO_TOKEN".into()),
    );
    json_roundtrip(SandboxDirective {
        exec: ExecBackend::Oci,
        fs: FsPolicy::Scratch,
        net: NetPolicy::Host,
        env,
        secret_tokens: tokens,
        image: None,
        confine_to_declared_inputs: false,
        content_cacheable: false,
        read_closure: Vec::new(),
        write_closure: Vec::new(),
        determinism_pinned: false,
    });
}

// ---- TOML round-trips (matches the authored schema) ----

#[test]
fn sandbox_profile_toml_roundtrip() {
    let profile = SandboxProfile {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRo,
        net: NetPolicy::Offline,
        secrets: BTreeMap::new(),
        locked: false,
        image: None,
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    };
    let s = toml::to_string(&profile).expect("toml serialize");
    let back: SandboxProfile = toml::from_str(&s).expect("toml deserialize");
    assert_eq!(profile, back);
}

#[test]
fn sandbox_profile_with_image_toml_roundtrip() {
    let profile = SandboxProfile {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRw,
        net: NetPolicy::Offline,
        secrets: BTreeMap::new(),
        locked: false,
        image: Some(SandboxImage {
            reference: "kata/rust-1.85:latest".into(),
            cpus: Some(4),
            memory_mb: Some(4096),
        }),
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    };
    let s = toml::to_string(&profile).expect("toml serialize");
    let back: SandboxProfile = toml::from_str(&s).expect("toml deserialize");
    assert_eq!(profile, back);
}

#[test]
fn exec_backend_toml_roundtrip() {
    // Wrap inside a struct because TOML's top-level value must be
    // a table. The tag/content serde shape is exercised through a containment
    // provider.
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Wrap {
        exec: ExecBackend,
    }
    let w = Wrap {
        exec: ExecBackend::Oci,
    };
    let s = toml::to_string(&w).unwrap();
    let back: Wrap = toml::from_str(&s).unwrap();
    assert_eq!(w, back);
}

// ---- the secret grant's one form ----

/// A `secret_tokens` entry is a [`SecretRef`] DECLARATION and nothing else: a bare
/// JSON string (a plaintext value) is refused at decode by the generic serde error,
/// while the declaration object decodes.
#[test]
fn a_bare_string_secret_token_entry_is_refused_at_decode() {
    let directive = SandboxDirective {
        exec: ExecBackend::Oci,
        fs: FsPolicy::Scratch,
        net: NetPolicy::Host,
        env: BTreeMap::new(),
        secret_tokens: BTreeMap::new(),
        image: None,
        confine_to_declared_inputs: false,
        content_cacheable: false,
        read_closure: Vec::new(),
        write_closure: Vec::new(),
        determinism_pinned: false,
    };
    let with_tokens = |tokens: serde_json::Value| {
        let mut value = serde_json::to_value(&directive).expect("encodes");
        value["secret_tokens"] = tokens;
        serde_json::from_value::<SandboxDirective>(value)
    };

    let error = with_tokens(serde_json::json!({"API": "bare-plaintext"}))
        .expect_err("a bare string is a plaintext value, not a declaration")
        .to_string();
    assert!(
        error.contains("invalid type: string"),
        "the refusal is the generic decode error for a string where a declaration belongs: \
         {error}"
    );

    let declared = with_tokens(serde_json::json!({"API": {"kind": "env", "data": "PROD_API"}}))
        .expect("a declaration decodes");
    assert_eq!(declared.secret_tokens.len(), 1);
}

// ---- the capsule's shared-filesystem presumption, enumerated ----

/// A directive presumes NOTHING about the main's filesystem — no field carries a
/// main-resolved path since the bwrap `/workspace` bind source was deleted.
#[test]
fn a_directive_presumes_nothing_about_the_mains_filesystem() {
    let mut env = BTreeMap::new();
    // Deliberately populated: a free-form env entry — even an absolute-path-shaped
    // one — is operator authorship, not a main-stamped bind source.
    env.insert("SOME_DIR".to_string(), "/opt/whatever".to_string());
    let directive = SandboxDirective {
        exec: ExecBackend::Oci,
        fs: FsPolicy::Scratch,
        net: NetPolicy::Offline,
        env,
        secret_tokens: BTreeMap::new(),
        image: None,
        confine_to_declared_inputs: true,
        content_cacheable: true,
        read_closure: vec![smol_str::SmolStr::new("src/**")],
        write_closure: Vec::new(),
        determinism_pinned: false,
    };
    assert!(
        directive.shared_filesystem_presumptions().is_empty(),
        "a directive names no main-resolved path"
    );
}

// ---------------------------------------------------------------------------
// `ToolchainRequirement`: a pack cannot contain a host path
// ---------------------------------------------------------------------------

/// THE STRUCTURAL PROPERTY. A toolchain requirement cannot hold a filesystem
/// path — not through the authoring parser, and not through serde either.
///
/// The two doors matter separately. `parse` is what a `.star` file goes through;
/// `Deserialize` is what a durable `ExecutionProgram` blob and a
/// `SandboxDirective` decoded off the wire go through. A type guarded at one door
/// is a type with a way around it, so this asserts both on the same inputs.
///
/// Portability is the reason and it is not abstract: a pack naming
/// `/home/alice/.rustup/toolchains/…` runs on Alice's box and, on any other,
/// either fails or silently binds something else. A content address names the
/// same toolchain everywhere or names nothing.
#[test]
fn a_toolchain_requirement_can_never_hold_a_host_path() {
    let hex = "a".repeat(64);
    let store_path = format!("/srv/kata/toolchains/{hex}");
    let prefixed_path = format!("store:/srv/kata/toolchains/{hex}");
    let suffixed = format!("store:{hex}/bin");
    for path in [
        "/usr",
        "/usr/local/rust",
        "./relative/toolchain",
        store_path.as_str(),
        prefixed_path.as_str(),
        suffixed.as_str(),
    ] {
        assert!(
            ToolchainRequirement::parse(path).is_none(),
            "the authoring door must refuse the path {path:?}"
        );
        let encoded = serde_json::to_string(path).expect("a string encodes");
        assert!(
            serde_json::from_str::<ToolchainRequirement>(&encoded).is_err(),
            "the serde door must refuse the path {path:?} too — a durable blob and a wire frame \
             reach this type without passing the authoring parser"
        );
    }
}

/// Only `store:<64 lowercase hex>` is a requirement: an `attested:` address and a
/// bare hex are both refused.
#[test]
fn a_toolchain_requirement_refuses_every_basis_but_the_store() {
    let hex = "b".repeat(64);
    assert!(
        ToolchainRequirement::parse(&format!("store:{hex}")).is_some(),
        "the store basis is the one a node can resolve"
    );
    for unresolvable in [format!("attested:{hex}"), hex.clone()] {
        assert!(
            ToolchainRequirement::parse(&unresolvable).is_none(),
            "{unresolvable} names no bytes any node can look up"
        );
    }
    let requirement =
        ToolchainRequirement::parse(&format!("store:{hex}")).expect("a store requirement parses");
    assert_eq!(requirement.to_string(), format!("store:{hex}"));
    assert_eq!(requirement.hex(), hex);
}

/// BYTE-LEVEL ABSENCE. A profile that declares no toolchain serializes no
/// `toolchain` key, so the field contributes nothing to any `program_hash`,
/// `contract_hash` or capsule permissions hash.
///
/// Asserted against a LITERAL object rather than against another
/// serialization of the same struct: comparing the type to itself would pass
/// however the encoding changed.
#[test]
fn a_profile_without_a_toolchain_encodes_no_toolchain_key() {
    let profile = SandboxProfile {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRo,
        net: NetPolicy::Offline,
        secrets: BTreeMap::new(),
        locked: false,
        image: None,
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(&profile).expect("a profile encodes"),
        serde_json::json!({
            "exec": {"kind": "oci"},
            "fs": {"kind": "workspace_ro"},
            "net": {"kind": "offline"},
            "locked": false,
        }),
        "an undeclared toolchain must contribute no bytes"
    );
}
