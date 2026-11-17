//! The NODE's environment: the one Nix closure `[node] environment` declares, realised,
//! verified, rooted and promoted at boot.
//!
//! # What this module is
//!
//! [`bind_node_environment`] is the environment plane's PRODUCTION caller. Before it, a
//! capsule's environment was read off whichever `nix_environments` row happened to be
//! active and promoted, and nothing in production wrote one. Now the node declares the
//! closure an operator named, BEFORE it reports ready, and the id that comes back is the
//! only one the capsule submit path selects (`Dispatcher::with_node_environment`). A pack
//! never names it: which closure a container runs in is a machine fact.
//!
//! # Refused set, each by name
//!
//! * [`NODE_ENVIRONMENT_PLATFORM_MISMATCH`] — the declaration's `system` is not this
//!   node's ([`kata_types::node_profile::node_platform`]), or this binary's target has no
//!   platform at all. Refused BEFORE any Nix call: nothing is realised for a platform the
//!   node cannot run.
//! * [`NODE_ENVIRONMENT_SUPERSEDED`] — the plane already holds an ACTIVE environment
//!   (promoted or not) whose id is not this declaration's. Refused after the id is
//!   derived and BEFORE anything is rooted, published or written.
//! * [`NODE_ENVIRONMENT_NIX_UNAVAILABLE`] — the node's store did not answer `nix store
//!   info` within the exec deadline (absent `nix`, a `nix` without the `nix-command`
//!   feature, a refused connection, a hung daemon). The remedy names both the feature and
//!   the daemon; nix's own text, carried in the refusal, says which.
//!   Every nix exec after it is bounded by the same deadline
//!   (`nix_exec_deadline_exceeded`).
//! * [`NODE_ENVIRONMENT_UNPROMOTED`] — the declaration committed but its row is not
//!   promoted. Defensive: `declare_environment` promotes before it returns, and ignores a
//!   `NoRootsFound` outcome on a first declaration, which is the one path that could
//!   leave the row unpromoted; this check is what keeps that from reaching readiness.
//! * everything `declare_environment` refuses (an absent store path, a verification
//!   failure, a signature policy the closure does not meet, a malformed manifest, a
//!   released id), verbatim.
//!
//! # Why a live PREVIOUS environment refuses boot rather than being released
//!
//! Two reasons. Releasing at boot would decide, on the operator's behalf,
//! that nothing from the previous boot still needs that closure — the release verb checks
//! for a live bound attempt, but boot is not the moment to make that call silently. And release is a RETENTION DECISION
//! the plane will not reverse (a released id is never re-declared), so a boot that
//! released on a config edit would make a one-character typo permanent. Choosing either
//! row would be kata deciding which closure a container reads. So the node refuses, and
//! the refusal names both ids and prints the previous declaration as TOML (read back from
//! its manifest in CAS); the recourse is to restore it, or to stop the node and run
//! `kata node environment release <id>`, which refuses while any non-terminal attempt's
//! capsule still binds that environment.
//!
//! # The cost of re-verifying on every boot, stated
//!
//! An unchanged re-boot re-runs the WHOLE declare prefix: `path-info --recursive` and
//! `nix store verify` under the declared policy (which, with `verify_contents_at_declare`,
//! re-hashes every byte of the closure). Deliberate: boot is the last moment a corrupted
//! or partially collected closure can be refused before a container binds it, and the
//! id alone cannot say the bytes are still there. The cost is bounded by the closure's
//! size and by the nix exec deadline.
//!
//! # Idempotence
//!
//! Every input folds into the manifest bytes and therefore into the id, and the manifest
//! carries no clock reading, so an unchanged declaration derives the same id on every
//! boot; `commit_declaration`'s step 6 recognises the stored row and stages no second gc
//! root and writes no second row.

use std::path::Path;

use kata_types::config::NodeEnvironmentConfig;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{EnvironmentId, PlatformId, PlatformRef};
use kata_types::nix_environment::{RetentionClass, RetentionIntent};

use super::declare::{self, DeclarationInput, DeclarationSource};
use super::nix::NixStore;
use super::roots;
use crate::OperationalDb;
use crate::store::cas::CasStore;

/// The declaration names a platform this node is not.
pub const NODE_ENVIRONMENT_PLATFORM_MISMATCH: &str = "node_environment_platform_mismatch";
/// The plane holds a different live environment from a previous boot.
pub const NODE_ENVIRONMENT_SUPERSEDED: &str = "node_environment_superseded";
/// The node's Nix store did not answer: absent, refusing, or hung past the exec deadline.
pub const NODE_ENVIRONMENT_NIX_UNAVAILABLE: &str = "node_environment_nix_unavailable";
/// The declaration committed without a promoted gc root.
pub const NODE_ENVIRONMENT_UNPROMOTED: &str = "node_environment_unpromoted";

/// The environment this node BOUND at boot: the id every capsule stage selects, and the
/// platform it was declared for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeEnvironment {
    pub environment: EnvironmentId,
    pub platform: PlatformId,
}

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("node environment refused at boot: {reason}"))
}

/// DECLARE, PROMOTE and BIND this node's environment, or refuse by name.
///
/// `node_platform` is a parameter rather than read here so a cell can drive the mismatch
/// arm on the one platform this code runs on; production passes
/// [`kata_types::node_profile::node_platform`] (and `None` on a target with no platform).
///
/// # Errors
///
/// The module docs' refused set.
pub fn bind_node_environment(
    db: &OperationalDb,
    cas: &CasStore,
    store: &NixStore,
    data_dir: &Path,
    declaration: &NodeEnvironmentConfig,
    node_platform: Option<&PlatformRef>,
) -> KataResult<NodeEnvironment> {
    let Some(node_platform) = node_platform else {
        return Err(refused(&format!(
            "{NODE_ENVIRONMENT_PLATFORM_MISMATCH}: this binary's target has no platform kata \
             qualifies (the initial target is x86_64-linux), so no closure declared as {:?} can \
             run on it",
            declaration.system
        )));
    };
    if declaration.system != node_platform.target() {
        return Err(refused(&format!(
            "{NODE_ENVIRONMENT_PLATFORM_MISMATCH}: `[node] environment` declares a closure \
             realised for {:?} and this node is {:?}. A container executes the closure's \
             binaries on this kernel, so a closure for another platform is not one this node \
             can bind. Nothing was realised, rooted or written",
            declaration.system,
            node_platform.target()
        )));
    }

    // THE STORE ANSWERS, or boot refuses by name — bounded, so a hung daemon is a
    // refusal and not a node that never starts.
    super::nix::store_reachable(store).map_err(|error| {
        refused(&format!(
            "{NODE_ENVIRONMENT_NIX_UNAVAILABLE}: the node's Nix store did not answer `nix store \
             info` ({error}). An `oci` node declares its closure at boot and cannot run a capsule \
             without it. The `nix` command needs Nix's `nix-command` feature \
             (`experimental-features = nix-command` in nix.conf) and a running Nix daemon; \
             enable the feature or start (or repair) the daemon, whichever nix named above, and \
             restart the node"
        ))
    })?;
    let prepared = declare::prepare_declaration(
        store,
        DeclarationInput {
            label: declaration.label.clone(),
            platform: node_platform.clone(),
            source: DeclarationSource::StorePaths {
                nixpkgs_attribute: declaration.nixpkgs_attribute.clone(),
                paths: declaration.store_paths.clone(),
            },
            path_prepend: declaration.path_prepend.clone(),
            integrity_policy: declaration.integrity_policy.clone(),
            // A node's environment is the reason its closure exists on this host, not a
            // cache entry that may be collected and re-realised.
            retention: RetentionIntent {
                class: RetentionClass::Authoritative,
            },
        },
    )?;
    let wanted = prepared.environment_ref().id();

    // BEFORE anything is rooted: a different live environment is refused, not chosen.
    // See the module docs for why neither "pick" nor "release" is taken.
    let others: Vec<_> = db
        .active_environments()?
        .into_iter()
        .filter(|row| row.environment_id != wanted.0.0)
        .collect();
    if !others.is_empty() {
        let names = others
            .iter()
            .map(|row| {
                format!(
                    "{} ({}) — declared as:\n{}",
                    roots::hex(&row.environment_id),
                    row.label,
                    previous_declaration_toml(cas, row.manifest_object_id)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(refused(&format!(
            "{NODE_ENVIRONMENT_SUPERSEDED}: this data directory holds live environment(s) {names} \
             from a previous boot, and `[node] environment` now declares {} ({}). kata will not \
             choose which closure this node's containers read. Either restore the previous \
             declaration (printed above, as TOML), or stop the node and release the previous \
             environment with `kata node environment release <id> --config <path>` (refused \
             while any non-terminal attempt still binds it), then start again. Nothing was \
             rooted or written",
            roots::hex(&wanted.0.0),
            declaration.label,
        )));
    }

    let bound = declare::commit_declaration(db, cas, store, data_dir, prepared)?;
    if bound.id() != wanted {
        // The store changed between the describe and the commit — two derivations of one
        // declaration disagreeing is not something to bind either of.
        return Err(KataError::Storage(format!(
            "node environment: the declaration derived {} before the commit and {} after it",
            roots::hex(&wanted.0.0),
            roots::hex(&bound.id().0.0)
        )));
    }
    let row = db.environment(wanted.0.0)?.ok_or_else(|| {
        KataError::Storage(format!(
            "node environment {} was declared and has no row",
            roots::hex(&wanted.0.0)
        ))
    })?;
    if row.root_promoted_at_ms.is_none() {
        return Err(refused(&format!(
            "{NODE_ENVIRONMENT_UNPROMOTED}: environment {} committed but its Nix gc root never \
             left staging, so its closure is collectable and no capsule may bind it",
            roots::hex(&wanted.0.0)
        )));
    }
    Ok(NodeEnvironment {
        environment: wanted,
        platform: node_platform.id(),
    })
}

/// The PROGRAM NAMES `environment` provides on its guest `PATH`: every executable regular
/// file directly inside one of its manifest's `path_prepend` directories, read off this
/// node's store (the store the capsule binds read-only, so a program present here is
/// present in the guest). Boot installs it as the node fact the `oci`
/// CHECK judges `sandbox_profile(requires = [..])` against.
///
/// # Errors
///
/// An environment with no row, or a manifest that does not decode. An unreadable
/// `PATH` directory contributes nothing (it provides no program).
pub fn environment_path_programs(
    db: &OperationalDb,
    cas: &CasStore,
    environment: EnvironmentId,
) -> KataResult<std::collections::BTreeSet<String>> {
    let row = db
        .environment(environment.0.0)?
        .ok_or_else(|| KataError::Storage(format!("environment {} has no row", environment.0)))?;
    let bytes = cas.get_verified_bounded(
        &kata_types::primitives::FixedBytes(row.manifest_object_id),
        kata_types::nix_environment::NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES,
    )?;
    let manifest: kata_types::nix_environment::NixEnvironmentManifest =
        serde_json::from_slice(&bytes).map_err(|error| {
            KataError::Serialization(format!(
                "environment {}'s manifest does not decode: {error}",
                environment.0
            ))
        })?;
    let mut programs = std::collections::BTreeSet::new();
    for dir in manifest.path_prepend() {
        dir_programs(dir.as_str(), &mut programs);
    }
    Ok(programs)
}

/// One `path_prepend` directory's programs: the EXECUTABLE REGULAR FILES only —
/// a non-executable file, a directory, or a symlink dangling to nothing is a
/// data file on `PATH`, not a program the `requires` door may satisfy; an
/// unreadable directory contributes nothing.
fn dir_programs(dir: &str, programs: &mut std::collections::BTreeSet<String>) {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let executable = std::fs::metadata(entry.path())
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0);
        if executable && let Some(name) = entry.file_name().to_str() {
            programs.insert(name.to_owned());
        }
    }
}

/// The declaration a stored environment was made from, as `[node.environment]` TOML read
/// back from its manifest in CAS — so "restore the previous declaration" is something an
/// operator can paste. Falls back to a sentence naming what could not be read.
fn previous_declaration_toml(cas: &CasStore, manifest_object: [u8; 32]) -> String {
    let render = || -> KataResult<String> {
        let bytes = cas.get_verified_bounded(
            &kata_types::primitives::FixedBytes(manifest_object),
            kata_types::nix_environment::NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES,
        )?;
        let manifest: kata_types::nix_environment::NixEnvironmentManifest =
            serde_json::from_slice(&bytes).map_err(|error| {
                KataError::Serialization(format!("manifest does not decode: {error}"))
            })?;
        let kata_types::nix_environment::Provenance::StorePaths { nixpkgs_attribute } =
            manifest.provenance()
        else {
            return Err(KataError::Validation(format!(
                "declared from `{}` provenance, which `[node] environment` has no form for",
                manifest.provenance().as_tag()
            )));
        };
        #[derive(serde::Serialize)]
        struct Node<'a> {
            environment: &'a NodeEnvironmentConfig,
        }
        #[derive(serde::Serialize)]
        struct Document<'a> {
            node: Node<'a>,
        }
        let config = NodeEnvironmentConfig {
            label: manifest.label().to_owned(),
            system: manifest.platform().target().to_owned(),
            nixpkgs_attribute: nixpkgs_attribute.clone(),
            store_paths: manifest.roots().to_vec(),
            path_prepend: manifest.path_prepend().to_vec(),
            integrity_policy: manifest.integrity_policy().clone(),
        };
        toml::to_string(&Document {
            node: Node {
                environment: &config,
            },
        })
        .map_err(|error| KataError::Serialization(format!("render TOML: {error}")))
    };
    render().unwrap_or_else(|error| {
        format!("(the previous declaration could not be read back: {error})")
    })
}

#[cfg(test)]
mod tests {
    use super::dir_programs;
    use std::os::unix::fs::PermissionsExt as _;

    /// A `path_prepend` directory's programs are its EXECUTABLE regular files —
    /// a 0644 file and a subdirectory are data on `PATH`, never programs the
    /// `requires` door may answer with.
    #[test]
    fn a_path_prepend_dir_counts_only_executable_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("real-tool");
        std::fs::write(&executable, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(bin.join("not-a-tool"), "data").unwrap();
        std::fs::create_dir(bin.join("a-subdir")).unwrap();
        let mut programs = std::collections::BTreeSet::new();
        dir_programs(bin.to_str().unwrap(), &mut programs);
        assert_eq!(
            programs.into_iter().collect::<Vec<_>>(),
            vec!["real-tool".to_owned()],
            "only the executable file is a program"
        );
        let mut unreadable = std::collections::BTreeSet::new();
        dir_programs("/nonexistent-dir-for-this-test", &mut unreadable);
        assert!(
            unreadable.is_empty(),
            "an unreadable directory contributes nothing"
        );
    }
}
