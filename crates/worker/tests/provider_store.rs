//! **An external provider is identified by CONTENT**, and this is where the
//! resolver is proven.
//!
//! # What is proven here, and what deliberately is not
//!
//! Proven: that an address resolves to bytes through a by-hash store; that a
//! store entry whose bytes were replaced is REFUSED rather than spawned; that a
//! verified entry holding no executable for the declared provider is refused;
//! and that a node with no store root is refused naming the key and a command.
//!
//! NOT proven here: that a provider resolved by digest is the binary that
//! actually RUNS. Every live OCI cell (`oci_provider_live.rs`, riding `just
//! oci-live-smoke`) spawns the provider this resolver returns, but no cell
//! observes the running process's own bytes against the resolved entry.
//!
//! # Host-independent, and rides `just gate`
//!
//! Everything here is a temp directory and a `blake3` hash. Nothing needs
//! namespaces, a delegated cgroup, or a provider process, and nothing declines
//! to assert for a host reason — so this is not capability-conditional and
//! `gate_exclusion.rs`'s containment-lane coverage check has no claim on it.

use kata_worker::{
    EXTERNAL_PROVIDER_ADDRESS_ENV, EXTERNAL_PROVIDER_ENV, EXTERNAL_PROVIDER_STORE_ENV,
    ExternalProviderAddress, ExternalProviderDeclaration, ProviderStore,
};

const PROVIDER: &str = "acme-provider";

/// A source tree holding one provider executable, ready to provision.
fn provider_source(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let source = dir.join(format!("src-{name}"));
    std::fs::create_dir_all(&source).expect("source dir");
    std::fs::write(source.join(format!("kata-provider-{name}")), bytes).expect("provider bytes");
    source
}

fn declaration(name: &str, address: &ExternalProviderAddress) -> ExternalProviderDeclaration {
    ExternalProviderDeclaration::parse(name, &address.to_string()).expect("declaration parses")
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// **The central property**: what an install PUBLISHED is what a declaration
/// RESOLVES, and the address is re-derived from the bytes on the way.
///
/// # Would RED if
///
/// * `resolve` looked the entry up by name without re-hashing it — see the
///   mutation row below, which is the counterfactual for exactly that;
/// * `provision` minted an address over the SOURCE rather than the copy;
/// * the entry layout and the resolver's expectation drifted apart.
#[test]
fn an_installed_provider_resolves_back_to_the_bytes_that_were_published() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it. `provision` SEALS its
    // entry to `0500`, and `TempDir`'s own `Drop` cannot remove a sealed tree —
    // `remove_dir_all` returns `EACCES` and a destructor has nowhere to report it,
    // so the directory silently survives the run. See `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let source = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    let store = ProviderStore::new(tmp.path().join("store"));

    let installed = store
        .provision(PROVIDER, &source)
        .expect("a directory holding kata-provider-<name> provisions");
    assert_eq!(installed.name, PROVIDER);
    assert!(
        installed.binary.is_file(),
        "the published entry must hold the executable: {}",
        installed.binary.display()
    );

    let resolved = store
        .resolve(&declaration(PROVIDER, &installed.address))
        .expect("the address just minted must resolve");
    assert_eq!(resolved.binary(), installed.binary);
    assert_eq!(resolved.address(), &installed.address);
    assert_eq!(resolved.name(), PROVIDER);

    // The address is a CONTENT address, so provisioning byte-identical bytes
    // twice is one entry. Without this the store would be a directory of
    // duplicates and "the name IS the contents" would be a claim about one
    // provision rather than a property.
    let again = provider_source(tmp.path(), "twin", b"unused");
    std::fs::remove_file(again.join("kata-provider-twin")).expect("clear the twin");
    std::fs::write(
        again.join(format!("kata-provider-{PROVIDER}")),
        b"#!/bin/sh\nexit 0\n",
    )
    .expect("identical bytes");
    let second = store
        .provision(PROVIDER, &again)
        .expect("identical bytes provision idempotently");
    assert_eq!(second.address, installed.address);
}

/// The exports `kata sandbox install-external-provider` prints route a node to
/// exactly the entry just provisioned: one `export KEY=VALUE` line per node key,
/// in [`kata_worker::NODE_PROVIDER_ENV_KEYS`] order, each carrying the
/// provisioned value. Values are written unquoted.
///
/// The expected text spells the key names out rather than reading them from the
/// key list, so a renamed key is caught here and not just carried along.
///
/// # Would RED if
///
/// `operator_exports` returned an empty string, dropped or reordered a key, or
/// paired a key with another key's value.
#[test]
fn the_operator_exports_name_every_node_key_with_its_provisioned_value() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it: see
    // `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let source = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    let root = tmp.path().join("store");
    let installed = ProviderStore::new(&root)
        .provision(PROVIDER, &source)
        .expect("a directory holding kata-provider-<name> provisions");

    let exports = installed.operator_exports(&root);
    let expected = format!(
        "export KATA_EXTERNAL_PROVIDER_STORE={root}\n\
         export KATA_EXTERNAL_EXECUTION_PROVIDER={PROVIDER}\n\
         export KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS={address}",
        root = root.display(),
        address = installed.address,
    );
    assert_eq!(exports, expected);
    let exported_keys: Vec<&str> = exports
        .lines()
        .map(|line| {
            line.strip_prefix("export ")
                .and_then(|rest| rest.split_once('='))
                .map(|(key, _)| key)
                .expect("every line is `export KEY=VALUE`")
        })
        .collect();
    assert_eq!(exported_keys, kata_worker::NODE_PROVIDER_ENV_KEYS);
    assert!(
        installed.address.to_string().starts_with("store:"),
        "the exported address is the store address form: {}",
        installed.address
    );
}

/// **The mutation counterfactual — this is what makes the round trip above mean
/// anything.**
///
/// The attack is a length-preserving substitution: a check cheaper than
/// reading the content is blind to it by construction. So the entry's bytes are
/// replaced with DIFFERENT bytes of the SAME length, and resolution must refuse.
///
/// # Would RED if
///
/// `resolve` did a name-only lookup. Measured: with `verify_store_entry`'s
/// verdict ignored, this row reports a successful resolution of the mutated
/// bytes — which is a provider kata would have spawned under an address that no
/// longer describes it.
#[test]
fn a_store_entry_whose_bytes_were_replaced_is_refused_rather_than_spawned() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it. `provision` SEALS its
    // entry to `0500`, and `TempDir`'s own `Drop` cannot remove a sealed tree —
    // `remove_dir_all` returns `EACCES` and a destructor has nowhere to report it,
    // so the directory silently survives the run. See `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let source = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    let store = ProviderStore::new(tmp.path().join("store"));
    let installed = store.provision(PROVIDER, &source).expect("provision");

    // PRECONDITION: it resolves BEFORE the mutation, or the refusal below is not
    // attributable to the mutation.
    store
        .resolve(&declaration(PROVIDER, &installed.address))
        .expect("premise: the unmutated entry resolves");

    // The store seals its entries (dirs 0500, files 0555), so an operator — or
    // an attacker with the same uid — has to unseal first. That is DEFENCE IN
    // DEPTH and never the guarantee, which is precisely why the guarantee is
    // re-derived from the bytes.
    kata_worker::unseal_tree(&installed.entry).expect("unseal");
    let original = std::fs::read(&installed.binary).expect("read");
    let mutated: Vec<u8> = original
        .iter()
        .map(|b| if *b == b'0' { b'1' } else { *b })
        .collect();
    assert_eq!(
        mutated.len(),
        original.len(),
        "premise: the substitution must PRESERVE the length, else this measures a size check"
    );
    assert_ne!(mutated, original, "premise: the bytes must actually change");
    std::fs::write(&installed.binary, &mutated).expect("substitute");

    let refusal = store
        .resolve(&declaration(PROVIDER, &installed.address))
        .expect_err("an entry whose contents no longer hash to its name must be REFUSED");
    let text = refusal.to_string();
    for needle in [
        EXTERNAL_PROVIDER_ADDRESS_ENV,
        installed.address.hex(),
        "install-external-provider",
    ] {
        assert!(
            text.contains(needle),
            "the refusal must name the key, the address it could not honour, and the action that \
             fixes it ({needle}): {text}"
        );
    }
}

/// A VERIFIED entry that holds no executable for the declared provider is
/// refused, and the refusal says what the entry actually holds.
///
/// The address picks the ENTRY and the name picks the executable inside it, so
/// this is the one failure the address alone cannot explain — and a refusal that
/// named only what it wanted is one an operator answers by guessing.
#[test]
fn a_verified_entry_holding_the_wrong_provider_is_refused_naming_what_it_holds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it. `provision` SEALS its
    // entry to `0500`, and `TempDir`'s own `Drop` cannot remove a sealed tree —
    // `remove_dir_all` returns `EACCES` and a destructor has nowhere to report it,
    // so the directory silently survives the run. See `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let source = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    let store = ProviderStore::new(tmp.path().join("store"));
    let installed = store.provision(PROVIDER, &source).expect("provision");

    let wrong =
        ExternalProviderDeclaration::parse("other-provider", &installed.address.to_string())
            .expect("a well-formed declaration naming a provider this entry does not hold");
    let refusal = store
        .resolve(&wrong)
        .expect_err("a verified entry is not automatically the provider that was declared");
    let text = refusal.to_string();
    assert!(
        text.contains("VERIFIES"),
        "the refusal must distinguish itself from a hash mismatch — the bytes ARE what the \
         address names, and the mistake is elsewhere: {text}"
    );
    assert!(
        text.contains(&format!("kata-provider-{PROVIDER}")),
        "the refusal must list what the entry holds, so an operator can see they named the wrong \
         one: {text}"
    );
    assert!(
        text.contains(EXTERNAL_PROVIDER_ENV),
        "and it must name the key that picks the executable: {text}"
    );
}

/// An absent entry is refused with an action, never with a search.
///
/// This is the arm a `PATH` fallback would sit on, and its refusal is where
/// identification by content is visible to an operator.
#[test]
fn an_absent_entry_is_refused_naming_the_store_and_the_install_command() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = ProviderStore::new(tmp.path().join("store"));
    let address = ExternalProviderAddress::parse(&format!("store:{}", "a".repeat(64)))
        .expect("a well-formed address");
    let refusal = store
        .resolve(&declaration(PROVIDER, &address))
        .expect_err("an address with no entry behind it must refuse");
    let text = refusal.to_string();
    for needle in [
        EXTERNAL_PROVIDER_STORE_ENV,
        "install-external-provider",
        "LOCATION",
    ] {
        assert!(
            text.contains(needle),
            "the refusal must name the store root, the command that installs into it, and the \
             reason kata does not go looking ({needle}): {text}"
        );
    }
}

/// `provision` refuses a source that is not a provider, in the operator's own
/// vocabulary.
///
/// Defect class (d): the by-hash store once shared its implementation with a
/// TOOLCHAIN store whose refusals talked about the directory holding `bin/`; an
/// operator installing a provider who read that would have been sent to a knob
/// that had nothing to do with their problem. The word stays refused.
#[test]
fn provision_refuses_a_non_provider_source_without_ever_saying_toolchain() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it. `provision` SEALS its
    // entry to `0500`, and `TempDir`'s own `Drop` cannot remove a sealed tree —
    // `remove_dir_all` returns `EACCES` and a destructor has nowhere to report it,
    // so the directory silently survives the run. See `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let store = ProviderStore::new(tmp.path().join("store"));

    let empty = tmp.path().join("empty");
    std::fs::create_dir_all(&empty).expect("dir");
    let refusal = store
        .provision(PROVIDER, &empty)
        .expect_err("a directory holding no kata-provider-<name> is not that provider");
    let text = refusal.to_string();
    assert!(
        text.contains(&format!("kata-provider-{PROVIDER}")),
        "the refusal must name the file it required: {text}"
    );
    assert!(
        !text.contains("toolchain"),
        "an operator installing a PROVIDER must never be shown the toolchain store's vocabulary: \
         {text}"
    );

    // A FILE rather than a directory — joint 1's shape, refused by name.
    let file = tmp.path().join("kata-provider-acme-provider");
    std::fs::write(&file, b"x").expect("write");
    let refusal = store
        .provision(PROVIDER, &file)
        .expect_err("a provider is provisioned as the DIRECTORY holding its executable");
    assert!(
        refusal.to_string().contains("not a directory"),
        "got: {refusal}"
    );

    // And a name the ROUTE would refuse cannot enter the store either: an
    // install that succeeded under a name every stage would then reject is a
    // recourse that works exactly once.
    let source = provider_source(tmp.path(), "oci", b"x");
    store
        .provision("oci", &source)
        .expect_err("a linked backend's spelling is not a provider name, at install time either");
}

// ---------------------------------------------------------------------------
// Declared members
// ---------------------------------------------------------------------------

/// Every regular file under `entry`, as `(relative path, executable, bytes)`,
/// read straight off the filesystem — not through the store's own hash.
fn entry_files(entry: &std::path::Path) -> Vec<(String, bool, Vec<u8>)> {
    use std::os::unix::fs::PermissionsExt;
    let mut files: Vec<(String, bool, Vec<u8>)> = std::fs::read_dir(entry)
        .expect("entry readable")
        .map(|child| {
            let path = child.expect("entry child").path();
            let mode = std::fs::symlink_metadata(&path)
                .expect("stat")
                .permissions()
                .mode();
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                mode & 0o111 != 0,
                std::fs::read(&path).expect("member bytes"),
            )
        })
        .collect();
    files.sort();
    files
}

/// A member declared beside the source provisions the SAME entry as the same
/// bytes sitting in the source directory: one address, one file set, the same
/// bytes and executable bits, read back off the filesystem.
///
/// # Would RED if
///
/// `provision_with_members` dropped the member, copied it under another name,
/// lost its executable bit, or hashed anything but the copied entry.
#[test]
fn a_declared_member_provisions_the_entry_the_same_bytes_in_the_source_do() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it: see
    // `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let member_bytes = b"\x7fELF not really, but bytes kata does not build\n";

    // The complete layout: the member sits in the source directory.
    let complete = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    std::fs::write(complete.join("ip"), member_bytes).expect("member in source");
    std::fs::set_permissions(complete.join("ip"), std::fs::Permissions::from_mode(0o755))
        .expect("member executable");
    let in_source = ProviderStore::new(tmp.path().join("store-a"))
        .provision(PROVIDER, &complete)
        .expect("the complete layout provisions");

    // The split layout: the source holds only the provider; the member is a
    // regular executable file elsewhere.
    let split = tmp.path().join("split");
    std::fs::create_dir_all(&split).expect("split dir");
    std::fs::write(
        split.join(format!("kata-provider-{PROVIDER}")),
        b"#!/bin/sh\nexit 0\n",
    )
    .expect("provider bytes");
    let elsewhere = tmp.path().join("elsewhere/bin/ip");
    std::fs::create_dir_all(elsewhere.parent().unwrap()).expect("elsewhere dir");
    std::fs::write(&elsewhere, member_bytes).expect("member elsewhere");
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o555))
        .expect("member executable");
    let declared = ProviderStore::new(tmp.path().join("store-b"))
        .provision_with_members(PROVIDER, &split, &[("ip", &elsewhere)])
        .expect("the split layout provisions");

    assert_eq!(declared.address, in_source.address);
    assert_eq!(
        (declared.files, declared.bytes),
        (in_source.files, in_source.bytes)
    );
    let files = entry_files(&declared.entry);
    assert_eq!(files, entry_files(&in_source.entry));
    assert!(
        files
            .iter()
            .any(|(name, exec, bytes)| name == "ip" && *exec && bytes == member_bytes),
        "the member is in the entry, executable, with its bytes: {:?}",
        files.iter().map(|(n, e, _)| (n, e)).collect::<Vec<_>>()
    );
    // The split source was not modified: the member went into the entry, not
    // into the operator's directory.
    assert!(!split.join("ip").exists());
}

/// A declared member that is a SYMLINK is refused by name and never followed:
/// the entry would otherwise hold either a link (not bytes kata owns) or bytes
/// the declaration never named. No entry is published.
#[test]
fn a_declared_member_that_is_a_symlink_is_refused_not_followed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let source = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    let real = tmp.path().join("real-ip");
    std::fs::write(&real, b"ip").expect("real member");
    let link = tmp.path().join("ip-link");
    std::os::unix::fs::symlink(&real, &link).expect("link");
    let root = tmp.path().join("store");

    let refusal = ProviderStore::new(&root)
        .provision_with_members(PROVIDER, &source, &[("ip", &link)])
        .expect_err("a symlink member is refused");
    let text = refusal.to_string();
    assert!(
        text.contains("not a regular file") && text.contains("ip-link"),
        "the refusal names the member path and why: {text}"
    );
    let published: Vec<_> = std::fs::read_dir(&root)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect()
        })
        .unwrap_or_default();
    assert!(published.is_empty(), "nothing was published: {published:?}");
}

/// A declared member may not shadow an entry the source directory already
/// holds, and its name must be one plain file name: either would make the
/// entry's contents depend on which of two answers won.
#[test]
fn a_declared_member_may_not_shadow_the_source_or_name_a_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _unseal = kata_worker::UnsealOnDrop::new(tmp.path());
    let source = provider_source(tmp.path(), PROVIDER, b"#!/bin/sh\nexit 0\n");
    std::fs::write(source.join("ip"), b"source ip").expect("source member");
    let member = tmp.path().join("ip");
    std::fs::write(&member, b"declared ip").expect("declared member");
    let store = ProviderStore::new(tmp.path().join("store"));

    let refusal = store
        .provision_with_members(PROVIDER, &source, &[("ip", &member)])
        .expect_err("a member the source already holds is refused");
    assert!(
        refusal.to_string().contains("already holds `ip`"),
        "got: {refusal}"
    );

    let clean = tmp.path().join("clean");
    std::fs::create_dir_all(&clean).expect("clean dir");
    std::fs::write(
        clean.join(format!("kata-provider-{PROVIDER}")),
        b"#!/bin/sh\nexit 0\n",
    )
    .expect("provider bytes");
    for name in ["", ".", "..", "bin/ip", "/ip"] {
        let refusal = store
            .provision_with_members(PROVIDER, &clean, &[(name, &member)])
            .expect_err("a member name that is not one plain file name is refused");
        assert!(
            refusal.to_string().contains("one plain file name"),
            "{name:?}: {refusal}"
        );
    }
}
