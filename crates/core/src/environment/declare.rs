//! The declare sequence: realise, verify, root, publish, commit, promote.
//!
//! # Invariant
//!
//! The ORDER is the contract, and every step depends on the previous one having
//! happened:
//!
//! ```text
//! validate                      -- refuse a malformed request before touching a store
//! realise / import              -- the closure's roots exist in the store
//! path-info --recursive         -- the closure and its metadata, as nix reports it
//! verify per policy             -- what kata REQUIRES before it binds bytes
//! build the manifest            -- refuses Private, a root outside its closure, a
//!                                  path_prepend outside it
//! derive the environment id     -- from the manifest bytes' CAS address
//! already declared?             -- identical closure -> the stored ref, no new roots
//! stage protected roots         -- the closure cannot be collected from here on
//!   [K14 fires]                 -- root staged, manifest NOT durable
//! cas.put_durable(manifest)     -- bytes before reference (trust boundary 2)
//! db.declare_environment        -- row + node-owned manifest cas_roots row, one txn
//!   [K15 fires]                 -- row durable, root still in its staging generation
//! promote                       -- env/<id> holds the root, staging generation dropped
//! ```
//!
//! # Why the id is derived BEFORE the bytes are published
//!
//! An [`EnvironmentRef`] is `(manifest CAS id, closure digest)`, and the manifest's
//! CAS id is `blake3` over its canonical bytes — so the id is knowable from the
//! bytes alone. Deriving it first is what makes re-declaration idempotent: the
//! second declare of an identical closure recognises the stored row BEFORE it
//! stages a second gc root, and therefore never presents the divergent
//! `root_stage_id` that `OperationalDb::declare_environment` refuses. The derived
//! address is checked against `put_durable`'s receipt, so the derivation cannot
//! drift from the store's own addressing without being caught.
//!
//! # Trust boundary
//!
//! ADR-0001 trust boundary 5. `path-info` is a METADATA QUERY and this module
//! never treats it as verification: the bytes are vouched for only by the
//! [`nix::verify`] call, and only to the extent the [`IntegrityPolicy`] asked for.
//! A policy with `verify_contents_at_declare` unset produces a manifest that
//! records exactly that, and no caller may read it as "the bytes were checked".

use std::path::PathBuf;

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, EnvironmentRef, GuestPath, PlatformRef,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NixEnvironmentManifest, Provenance, RetentionIntent, StorePath,
};
use smol_str::SmolStr;

use super::nix::{self, NixStore, PathInfo};
use super::roots;
use crate::operational::EnvironmentDeclaration;
use crate::store::cas::CasStore;
use crate::{OperationalDb, operational};

/// Where the closure comes from.
///
/// This is the REALISATION instruction, not the manifest's [`Provenance`]: the
/// manifest records what happened, this records what to do.
#[derive(Clone, Debug)]
pub enum DeclarationSource {
    /// Store paths the caller already realised, plus the nixpkgs attribute they
    /// came from. The declare-time default: a flake reference is resolved to store paths before a
    /// declaration exists.
    StorePaths {
        nixpkgs_attribute: SmolStr,
        paths: Vec<StorePath>,
    },
    /// A tree on this host, imported with `nix store add-path`.
    ///
    /// `source_artifact` is the caller's ALREADY-PUBLISHED artifact naming these
    /// bytes. This module does not publish it and does not invent one: a
    /// `Provenance::ImportedTree` naming an artifact nobody published would be a
    /// dangling reference in the manifest, which is the shape trust boundary 2
    /// exists to prevent.
    ImportedTree {
        source: PathBuf,
        source_artifact: ArtifactId,
    },
}

/// Everything a declaration needs, and nothing a store can decide.
#[derive(Clone, Debug)]
pub struct DeclarationInput {
    pub label: String,
    pub platform: PlatformRef,
    pub source: DeclarationSource,
    /// `PATH` entries, in authored order. Each must be one of the closure's store
    /// paths or under one; the manifest refuses anything else.
    pub path_prepend: Vec<GuestPath>,
    pub integrity_policy: IntegrityPolicy,
    pub retention: RetentionIntent,
}

/// Declare one Nix environment and leave it BINDABLE.
///
/// Returns the [`EnvironmentRef`] the capsule plane binds. `environment_id` in
/// `operational.db` is `EnvironmentRef::id()`'s bytes, so the durable row and the
/// portable reference name the same thing by construction rather than by a
/// mapping someone has to maintain.
///
/// # Failure
///
/// Refuses, exactly:
///
/// * an empty `label`, or an [`IntegrityPolicy`] that advertises signature
///   enforcement while requiring no signature;
/// * `StorePaths` with no paths — an environment over an empty closure binds
///   nothing;
/// * any named store path that is not valid in `store` (`MissingPath`);
/// * a closure that fails `nix store verify --no-trust` under the policy — the
///   `narHash` mismatch case included, which is the one refusal a metadata query
///   cannot make;
/// * every refusal [`NixEnvironmentManifest::new`] makes: `Private` privacy, a
///   root outside its own closure, a `path_prepend` entry under no closure path, a
///   duplicate closure entry, a dangling reference index, a `narHash` that is not
///   shaped like SRI `sha256-<base64>`;
/// * a re-declaration of a RELEASED environment, refused by
///   `OperationalDb::declare_environment` — release is a retention decision this
///   path will not silently reverse.
///
/// An identical re-declaration of an ACTIVE environment is an idempotent no-op
/// returning the same ref. It stages no second gc root, and if the stored row is
/// unpromoted it finishes that promotion rather than starting over.
pub fn declare_environment(
    db: &OperationalDb,
    cas: &CasStore,
    store: &NixStore,
    data_dir: &std::path::Path,
    input: DeclarationInput,
) -> KataResult<EnvironmentRef> {
    let prepared = prepare_declaration(store, input)?;
    commit_declaration(db, cas, store, data_dir, prepared)
}

/// A declaration whose closure has been realised, verified and described, and whose
/// environment id is therefore KNOWN — with nothing yet rooted, published or written.
///
/// The split exists for a caller that must decide something about the id BEFORE the
/// declaration becomes durable: `bind_node_environment` refuses a node whose plane
/// already holds a DIFFERENT live environment, and deciding that after the commit would
/// leave the new row behind as the "other" environment the next boot refuses over.
#[derive(Debug)]
pub struct PreparedDeclaration {
    input: DeclarationInput,
    evidence: Vec<u8>,
    manifest: NixEnvironmentManifest,
    manifest_bytes: Vec<u8>,
    prospective: ArtifactId,
    environment_ref: EnvironmentRef,
}

impl PreparedDeclaration {
    /// The reference [`commit_declaration`] will return for this declaration.
    #[must_use]
    pub fn environment_ref(&self) -> &EnvironmentRef {
        &self.environment_ref
    }
}

/// Steps 1-5 of the declare sequence: validate, realise or import, describe, verify,
/// build the manifest and derive the id. Writes NOTHING kata owns (an `ImportedTree`
/// source is added to the Nix store, which is the realisation itself).
///
/// # Errors
///
/// The pre-root half of [`declare_environment`]'s refused set.
pub fn prepare_declaration(
    store: &NixStore,
    input: DeclarationInput,
) -> KataResult<PreparedDeclaration> {
    if input.label.is_empty() {
        return Err(KataError::Validation(
            "a Nix environment declaration requires a non-empty label".to_owned(),
        ));
    }
    input.integrity_policy.validate()?;

    // 1 — realise or import, so the roots exist in the store.
    let (roots_requested, provenance) = match &input.source {
        DeclarationSource::StorePaths {
            nixpkgs_attribute,
            paths,
        } => {
            if paths.is_empty() {
                return Err(KataError::Validation(
                    "a Nix environment declared over explicit store paths requires at least one; \
                     an environment over an empty closure binds nothing"
                        .to_owned(),
                ));
            }
            for path in paths {
                if !nix::path_exists(store, path)? {
                    return Err(KataError::Validation(format!(
                        "nix store does not contain {}; kata inherits the host's answer and \
                         refuses to realise one on its behalf",
                        path.as_str()
                    )));
                }
            }
            (
                paths.clone(),
                Provenance::StorePaths {
                    nixpkgs_attribute: nixpkgs_attribute.clone(),
                },
            )
        }
        DeclarationSource::ImportedTree {
            source,
            source_artifact,
        } => {
            let imported = nix::add_path(store, source)?;
            (
                vec![imported],
                Provenance::ImportedTree {
                    source_artifact: *source_artifact,
                },
            )
        }
    };

    // 2 — the closure and its metadata, as nix reports it. NOT verification.
    let closure_info = nix::path_info_recursive(store, &roots_requested)?;
    // 3 — what kata REQUIRES before it binds these bytes.
    let closure_paths: Vec<StorePath> = closure_info.iter().map(|info| info.path.clone()).collect();
    nix::verify(store, &closure_paths, &input.integrity_policy)?;
    refuse_unsatisfied_signature_policy(&closure_info, &input.integrity_policy)?;

    // 4 — the manifest, which refuses everything a declaration may not claim.
    let manifest = NixEnvironmentManifest::new(
        input.label.clone(),
        input.platform.clone(),
        provenance,
        roots_requested.clone(),
        closure_entries(&closure_info),
        input.path_prepend.clone(),
        input.integrity_policy.clone(),
        ArtifactPrivacy::Public,
        input.retention,
        realised_by(store),
    )?;
    let manifest_bytes = manifest.manifest_bytes()?;
    // 5 — the id, from the bytes' CAS address. See the module docs.
    let prospective = kata_types::nix_environment::environment_manifest_id(&manifest_bytes);
    let environment_ref = manifest.environment_ref(prospective);
    Ok(PreparedDeclaration {
        input,
        evidence: closure_evidence(&closure_info)?,
        manifest,
        manifest_bytes,
        prospective,
        environment_ref,
    })
}

/// Steps 6-9 of the declare sequence over a [`PreparedDeclaration`]: the idempotence
/// check, the staged root, the published manifest, the row, the promotion.
///
/// # Errors
///
/// The post-describe half of [`declare_environment`]'s refused set.
pub fn commit_declaration(
    db: &OperationalDb,
    cas: &CasStore,
    store: &NixStore,
    data_dir: &std::path::Path,
    prepared: PreparedDeclaration,
) -> KataResult<EnvironmentRef> {
    let PreparedDeclaration {
        input,
        evidence,
        manifest,
        manifest_bytes,
        prospective,
        environment_ref,
    } = prepared;
    let environment_id = environment_ref.id().0.0;

    // 6 — idempotence, BEFORE a second gc root exists.
    if let Some(stored) = db.environment(environment_id)? {
        // A RELEASED id is refused HERE, before `stage_roots`, rather than left to
        // the durable refusal downstream. The durable one stays as the backstop,
        // but reaching it would mean this path had already created a gc root and a
        // staging generation for an environment it was never going to declare —
        // residue the boot sweep would have to clean up after a refusal that was
        // knowable before any root existed.
        // A RELEASED id is refused HERE, before `stage_roots`, and BEFORE the
        // rootless check below. Two reasons, and only the second is about ordering.
        //
        // The REASON has to be right: a released row has had its links removed, so
        // the rootless check would also refuse it — with "holds NO gc root" and the
        // advice "release the row and declare the closure again", which misdescribes
        // an already-released environment and prescribes something nonsensical for
        // it. Release is a retention DECISION, and the refusal has to say so.
        //
        // And the durable refusal in `OperationalDb::declare_environment` stays as
        // the backstop rather than the primary: reaching it would mean this path had
        // already staged a gc root for an environment it was never going to declare.
        if stored.released_at_ms.is_some() {
            return Err(KataError::Validation(format!(
                "Nix environment {} was RELEASED and will not be re-declared: release is a \
                 retention decision about this closure, and re-declaring would silently reverse \
                 it. Any change to the declaration (its label, for one) mints a NEW environment \
                 id; declare that instead. No gc root was staged",
                roots::hex(&environment_id)
            )));
        }
        // An ACTIVE row is only an idempotent answer if its gc root is actually there.
        //
        // A ROOTLESS row is RE-ROOTED rather than refused, and the argument is the id: the
        // closure was just realised, described and VERIFIED above under the declared
        // policy, and it derived THIS id — so the store holds exactly the bytes the row
        // names (the id folds every entry's narHash and narSize). Re-staging its roots
        // under the stored generation and promoting is the same operation the first
        // declaration performed; it manufactures no root over bytes nobody checked.
        if roots::read_links(&roots::environment_directory(data_dir, environment_id))?.is_empty()
            && roots::read_links(&roots::staging_directory(data_dir, &stored.root_stage_id))?
                .is_empty()
        {
            roots::stage_roots(store, data_dir, &stored.root_stage_id, manifest.roots())?;
        }
        if stored.root_promoted_at_ms.is_none()
            || roots::read_links(&roots::environment_directory(data_dir, environment_id))?
                .is_empty()
        {
            let outcome =
                finish_promotion(db, store, data_dir, environment_id, &stored.root_stage_id)?;
            if outcome == roots::PromoteOutcome::NoRootsFound {
                return Err(rootless_redeclaration(
                    environment_id,
                    &stored.root_stage_id,
                    manifest.roots(),
                ));
            }
        }
        db.record_environment_evidence(environment_id, &evidence)?;
        return Ok(environment_ref);
    }

    // 7 — the closure becomes uncollectable.
    let stage_id = ulid::Ulid::new().to_string();
    roots::stage_roots(store, data_dir, &stage_id, manifest.roots())?;

    // 8 — bytes before reference. K14 fires inside `declare_environment`, between
    // this receipt and the row; see that method's crash-boundary section.
    let durable = cas.put_durable(&manifest_bytes)?;
    if durable.object_id() != prospective.0 {
        return Err(KataError::Storage(format!(
            "the CAS addressed the manifest as {} but this path derived the environment id from \
             {}; the derivation and the store disagree about content addressing and no \
             environment will be declared",
            roots::hex(&durable.object_id().0),
            roots::hex(&prospective.0.0)
        )));
    }
    db.declare_environment(
        &EnvironmentDeclaration::for_staged_root(
            environment_id,
            &durable,
            manifest.closure_digest().0,
            &input.label,
            input.platform.id().0.0,
            &stage_id,
        )?
        .with_verification_evidence(evidence),
    )?;

    // 9 — K15's far edge: hold the root at its stable path and record it.
    finish_promotion(db, store, data_dir, environment_id, &stage_id)?;
    Ok(environment_ref)
}

/// Move the gc root to its stable path and record the promotion.
///
/// Shared by the declare path and by [`super::reconcile`], so a recovered
/// promotion and a first-run promotion are the SAME operation rather than two
/// implementations that have to agree.
pub(super) fn finish_promotion(
    db: &OperationalDb,
    store: &NixStore,
    data_dir: &std::path::Path,
    environment_id: [u8; 32],
    stage_id: &str,
) -> KataResult<roots::PromoteOutcome> {
    let outcome = roots::promote(store, data_dir, environment_id, stage_id)?;
    if outcome == roots::PromoteOutcome::NoRootsFound {
        // Deliberately NOT recorded as promoted. A row whose root is gone is the
        // state `reconcile_environments` reports as unavailable; stamping it
        // promoted would advertise a bindable environment with nothing holding
        // its closure.
        return Ok(outcome);
    }
    db.promote_environment_root(environment_id, operational::now_ms())?;
    Ok(outcome)
}

/// Refuse a declared row whose gc root is gone.
///
/// Recorded as a VALIDATION refusal rather than repaired: this path cannot
/// re-create the root, because a root whose store object a collection already took
/// is not something to re-stage — the bytes are gone and re-realising them would be
/// a different closure decision than the one the row records.
fn rootless_redeclaration(
    environment_id: [u8; 32],
    stage_id: &str,
    roots_wanted: &[StorePath],
) -> KataError {
    KataError::Validation(format!(
        "Nix environment {} is declared but its gc root could not be re-established (staging \
         generation {stage_id}): a closure root is absent from the store. Realise it again — \
         `nix-store --realise {}` — and restart; the declaration then re-roots the same bytes, \
         because the id is a function of their content",
        roots::hex(&environment_id),
        roots_wanted
            .iter()
            .map(StorePath::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    ))
}

/// Enforce the two [`IntegrityPolicy`] fields `nix store verify` cannot express.
///
/// # Refused set
///
/// Over the closure's reported signatures and `ca`, exactly:
///
/// * a NON-EMPTY `required_signers` with an entry carrying no signature whose KEY
///   NAME — the part before the first `:` of a `<key name>:<base64>` signature —
///   is in the set. nix's `--sigs-needed N` is a COUNT over whatever keys the
///   store happens to trust; it cannot name a key, so a policy that names one and
///   relies on nix alone enforces nothing;
/// * `allow_unsigned_content_addressed == false` with a content-addressed entry
///   that carries no signature at all. nix always accepts such an object —
///   measured on 2.34.8, a CA path passes `--sigs-needed 1` at exit 0 — because
///   its address is its evidence, so a policy that declines that rule has to be
///   the one enforcing it.
///
/// Nothing else: an empty `required_signers` is satisfied by any key (the count is
/// nix's job), and `sigs_needed` itself is NOT re-counted here, because
/// [`nix::verify`] enforces it against the store's trusted-key set, which this
/// process cannot see.
fn refuse_unsatisfied_signature_policy(
    closure: &[PathInfo],
    policy: &IntegrityPolicy,
) -> KataResult<()> {
    for entry in closure {
        if !policy.required_signers.is_empty() {
            let signed_by_a_required_key = entry.signatures.iter().any(|signature| {
                signature.split_once(':').is_some_and(|(key, _)| {
                    policy
                        .required_signers
                        .iter()
                        .any(|required| required.as_str() == key)
                })
            });
            if !signed_by_a_required_key {
                return Err(KataError::Validation(format!(
                    "nix closure entry {} carries no signature from any required signer ({}); it \
                     is signed by [{}]. `nix store verify --sigs-needed` counts signatures and \
                     cannot name a key, so this refusal is kata's or it is nobody's",
                    entry.path.as_str(),
                    policy.required_signers.join(", "),
                    entry
                        .signatures
                        .iter()
                        .filter_map(|signature| signature.split_once(':').map(|(key, _)| key))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        if !policy.allow_unsigned_content_addressed
            && entry.ca.is_some()
            && entry.signatures.is_empty()
        {
            return Err(KataError::Validation(format!(
                "nix closure entry {} is content-addressed and UNSIGNED, and this policy does not \
                 allow an unsigned content-addressed object. Nix accepts one unconditionally — \
                 its address is its evidence — so this refusal cannot come from the store",
                entry.path.as_str()
            )));
        }
    }
    Ok(())
}

/// Turn nix's metadata into manifest closure entries.
///
/// `references` become INDICES into `infos` — which is the list
/// `NixEnvironmentManifest::new` receives, so its sort permutation remaps them.
/// A reference nix reports that is not in the closure is dropped: `path-info
/// --recursive` is closed by construction, so this cannot happen, and building a
/// dangling index instead would trip the manifest's closedness refusal with a
/// message about kata's own bug rather than about the declaration.
fn closure_entries(infos: &[PathInfo]) -> Vec<ClosureEntry> {
    let index_of = |path: &StorePath| -> Option<u32> {
        infos
            .iter()
            .position(|info| info.path == *path)
            .and_then(|index| u32::try_from(index).ok())
    };
    infos
        .iter()
        .enumerate()
        .map(|(own, info)| ClosureEntry {
            store_path: info.path.clone(),
            nar_hash: info.nar_hash.clone(),
            nar_size: info.nar_size,
            references: info
                .references
                .iter()
                .filter_map(index_of)
                // A self-reference is normal in Nix and is NOT a closure edge the
                // manifest accepts; `NixEnvironmentManifest::new` refuses an entry
                // that references its own index.
                .filter(|reference| usize::try_from(*reference).ok() != Some(own))
                .collect(),
            ca: info.ca.clone(),
        })
        .collect()
}

/// What the store REPORTED about each closure entry beyond its content — the signatures
/// and deriver the environment id no longer folds — as canonical JSON, the evidence
/// `nix_environments.verification_evidence` records.
fn closure_evidence(infos: &[PathInfo]) -> KataResult<Vec<u8>> {
    let mut evidence: Vec<kata_types::nix_environment::ClosureEvidence> = infos
        .iter()
        .map(|info| kata_types::nix_environment::ClosureEvidence {
            store_path: info.path.clone(),
            deriver: info.deriver.clone(),
            signatures: info.signatures.clone(),
        })
        .collect();
    evidence.sort_by(|left, right| left.store_path.cmp(&right.store_path));
    serde_json::to_vec(&evidence).map_err(|error| {
        KataError::Serialization(format!("nix closure evidence does not serialize: {error}"))
    })
}

/// Which store realised the closure, as a manifest field.
///
/// A [`NixStore::Local`] directory is a HOST PATH and never appears: the manifest
/// is portable and ADR-0001 forbids main-host paths in it. The tag names the kind.
fn realised_by(store: &NixStore) -> &'static str {
    match store {
        NixStore::Daemon => "nix-daemon",
        NixStore::Local(_) => "nix-local-store",
    }
}
