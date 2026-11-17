//! How a WORKER turns the two ids a capsule names
//! into the bytes they stand for, and refuses a plane that lies about either.
//!
//! # The problem this module exists for
//!
//! A capsule names its environment by [`EnvironmentId`] and each input by
//! [`ArtifactId`]. Both are `blake3` over FIELDS, so both are ONE-WAY: the id alone
//! cannot produce the object to read. Something has to hold the pairing, and the only
//! thing that does is the main's `operational.db` — `nix_environments.manifest_object_id`
//! and `artifacts.object_id`.
//!
//! So the worker reads those rows. It reads them READ-ONLY and it does not trust them:
//!
//! # THE VERIFICATION, and why it makes an untrusted row safe to read
//!
//! Every id this module resolves is a HASH OF THE THING IT POINTS AT:
//!
//! * `ArtifactId = H(object, size, privacy)` — so given the bytes at `object`, their
//!   length, and the privacy the `artifacts` ROW records (bytes declare no privacy), the
//!   id RECOMPUTES;
//! * `EnvironmentId = H(manifest ArtifactId, closure_digest)` — and
//!   [`NixEnvironmentManifest::closure_digest`] is computed field-wise from the manifest
//!   body, so that recomputes too.
//!
//! [`resolve_environment`] and [`LocalPlaneIndex`]'s [`TreeResolver`] therefore END with
//! a comparison of the RECOMPUTED id against the id the CAPSULE named. A row that points
//! an id at another object's bytes is refused by name
//! (`environment_identity_mismatch` / `artifact_identity_mismatch`), because the capsule
//! is content-addressed and the row is not: the capsule's id is the authority and the row
//! is a hint about where to look.
//!
//! That is what makes this a lookup rather than a trust relationship, and it is why the
//! worker may read a plane it does not own.
//!
//! # The shared-disk assumption, stated once
//!
//! [`LocalPlaneIndex`] opens `operational.db` and `cas.db` by path, read-only, exactly as
//! [`crate::materialize::LocalCasBlobSource`] does and for the same reason: today every
//! enrollment door refuses a worker outside the main's filesystem namespace. The
//! assumption lives at the TRAITS ([`EnvironmentIndex`], [`TreeResolver`],
//! [`BlobSource`]) so removing it later is a new impl rather than a rewrite — the
//! composition above this module never names a path or a database.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{ArtifactId, ArtifactPrivacy, ArtifactRef, EnvironmentId};
use kata_types::nix_environment::NixEnvironmentManifest;
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::TreeManifest;

use crate::materialize::{BlobSource, LocalCasBlobSource, TreeResolver};

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("capsule plane lookup refused: {reason}"))
}

/// Where one CAS object is, and how long it is — a row's CLAIM, not yet a fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectClaim {
    /// The CAS address the plane says holds the bytes.
    pub object: ObjectId,
    /// The length the CAS records for that object.
    pub size_bytes: u64,
}

/// The state of the `nix_environments` row an [`EnvironmentId`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvironmentClaim {
    /// Where the manifest bytes are.
    pub manifest: ObjectClaim,
    /// Whether the row has been RELEASED. A released environment is refused at
    /// execution even though the main's authorization gate already checked it: the two
    /// checks are at different INSTANTS, and the release that matters here is the one
    /// that happened after the attempt was authorized.
    pub released: bool,
    /// Whether the Nix gc root has been promoted out of staging. An unpromoted root is
    /// not bindable, so binding its paths would be binding a directory the reconciler
    /// still owes.
    pub root_promoted: bool,
}

/// How a worker finds the manifest bytes for an [`EnvironmentId`].
///
/// A trait for [`BlobSource`]'s reason: production reads a row on a shared disk, a rig
/// answers from a value it holds, and the composition above must not be able to tell.
pub trait EnvironmentIndex: Send + Sync {
    /// The claim this plane makes about `environment`, or `None` when it holds no row.
    ///
    /// # Errors
    ///
    /// Only an unreadable plane. A row that disagrees with the bytes is not this
    /// method's refusal — see [`resolve_environment`], which owns the verification.
    fn environment_claim(&self, environment: EnvironmentId)
    -> KataResult<Option<EnvironmentClaim>>;
}

/// RESOLVE the environment a capsule names into the manifest it stands for, verified
/// against the id.
///
/// # Failure — the refused set, stated exactly
///
/// Five things, each named:
///
/// 1. **`environment_unknown_to_this_worker`** — the plane holds no `nix_environments`
///    row for the id. A worker cannot invent a closure, and there is nothing weaker to
///    fall back to.
/// 2. **`environment_released`** — the row is released. Checked HERE and not only at
///    authorization because the release may have happened since; see
///    [`EnvironmentClaim::released`].
/// 3. **`environment_root_unpromoted`** — the gc root has not left staging, so its paths
///    are not bindable.
/// 4. **`environment_manifest_unreadable`** — the CAS does not hold the object the row
///    names, holds it at a different length, or the bytes do not decode as a manifest.
///    The store's own verified read refuses the first two before it allocates; the bound
///    is [`NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES`], the one the main authorizes under.
/// 5. **`environment_identity_mismatch`** — the manifest's own recomputed
///    [`EnvironmentId`] is not the one the capsule named. THIS is the check that makes
///    reading an untrusted row safe: the row said "look here" and the bytes here are a
///    DIFFERENT environment.
///
/// Nothing else. In particular this door does NOT check that the closure's store paths
/// are present on this host: that is [`crate::materialize`]'s
/// `environment_closure_incomplete`, which runs before a byte is written and is the one
/// place a closure's presence is decided. A second, weaker answer here would be two
/// refused sets to keep in agreement.
pub fn resolve_environment(
    index: &dyn EnvironmentIndex,
    source: &dyn BlobSource,
    environment: EnvironmentId,
) -> KataResult<NixEnvironmentManifest> {
    let claim = index.environment_claim(environment)?.ok_or_else(|| {
        refused(&format!(
            "environment_unknown_to_this_worker: this worker's plane holds no nix_environments \
             row for environment {}, which the capsule binds. A worker cannot invent a closure: \
             the environment was declared on the main that authorized this attempt, so either \
             this worker is reading a different data directory or the declaration was pruned",
            environment.0
        ))
    })?;
    if claim.released {
        return Err(refused(&format!(
            "environment_released: environment {} is RELEASED on this worker's plane. The main's \
             authorization gate checked this too, at an earlier instant; a release between then \
             and now is exactly what this check is for, and its bytes may already be collected",
            environment.0
        )));
    }
    if !claim.root_promoted {
        return Err(refused(&format!(
            "environment_root_unpromoted: environment {}'s Nix gc root has not left staging, so \
             its store paths are not bindable. The boot reconciler owes this promote",
            environment.0
        )));
    }
    let bytes = source
        .read_verified(
            claim.manifest.object,
            claim.manifest.size_bytes,
            NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES,
        )
        .map_err(|error| {
            refused(&format!(
                "environment_manifest_unreadable: environment {}'s manifest object {} ({} bytes \
                 claimed) is not readable from this worker's content store: {error}",
                environment.0, claim.manifest.object, claim.manifest.size_bytes
            ))
        })?;
    let manifest: NixEnvironmentManifest = serde_json::from_slice(&bytes).map_err(|error| {
        refused(&format!(
            "environment_manifest_unreadable: environment {}'s manifest object {} does not decode \
             as a nix environment manifest: {error}",
            environment.0, claim.manifest.object
        ))
    })?;
    // THE TWO-CARRIER CHECK. The row is a hint; the capsule's id is the authority.
    //
    // The manifest's artifact id is the BYTES' OWN CAS ADDRESS — the derivation
    // `kata_core::environment::declare_environment` mints the environment id from, reached
    // through the same `environment_manifest_id` rather than restated. It is NOT
    // `ArtifactRef::new(object, size, privacy).id()`: the ARTIFACT plane folds a length and
    // a privacy class into an artifact id, and the ENVIRONMENT plane folds neither, because
    // a manifest is always `Public` and its length is inside the address. Spelling the
    // wrong one here would recompute a different id for a correct row and refuse it.
    let manifest_artifact = kata_types::nix_environment::environment_manifest_id(&bytes);
    let recomputed = manifest.environment_ref(manifest_artifact).id();
    if recomputed != environment {
        return Err(refused(&format!(
            "environment_identity_mismatch: the capsule binds environment {wanted}, and the row \
             pointing at manifest object {object} holds an environment whose own recomputed id is \
             {found} (label {label}). An environment id folds the manifest's artifact id and its \
             closure digest, so this is a DIFFERENT closure — the row's pairing is a hint and the \
             capsule's id is the authority",
            wanted = environment.0,
            object = claim.manifest.object,
            found = recomputed.0,
            label = manifest.label(),
        )));
    }
    Ok(manifest)
}

/// [`EnvironmentIndex`] + [`TreeResolver`] + [`BlobSource`] over the node's OWN planes,
/// opened read-only by path.
///
/// One type for all three because they share one assumption (the worker and the
/// publisher share a disk) and one verification rule (an id is a hash of what it points
/// at). Three separate types would have stated the assumption three times and invited a
/// fourth reader that states it differently.
pub struct LocalPlaneIndex {
    operational: Mutex<rusqlite::Connection>,
    operational_path: PathBuf,
    cas: LocalCasBlobSource,
}

impl std::fmt::Debug for LocalPlaneIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalPlaneIndex")
            .field("operational_path", &self.operational_path)
            .field("cas", &self.cas)
            .finish_non_exhaustive()
    }
}

impl LocalPlaneIndex {
    /// Open `operational.db`, `cas.db` and the blob tree beneath `data_dir`, all
    /// read-only.
    ///
    /// # Errors
    ///
    /// An absent `operational.db`, and everything [`LocalCasBlobSource::open`] refuses
    /// (an absent `cas.db`, a blob tree that is not a directory). Refused HERE rather
    /// than at the first read, so a worker that cannot see the planes says so once, with
    /// the paths.
    pub fn open(data_dir: &Path) -> KataResult<Self> {
        let operational_path = data_dir.join("operational.db");
        if !operational_path.is_file() {
            return Err(refused(&format!(
                "operational plane {} is absent or is not a regular file; a capsule names its \
                 environment and its inputs by id, and this is the only plane that holds where \
                 those bytes are",
                operational_path.display()
            )));
        }
        let operational = rusqlite::Connection::open_with_flags(
            &operational_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            refused(&format!(
                "open operational plane {} read-only: {error}",
                operational_path.display()
            ))
        })?;
        let cas = LocalCasBlobSource::open(&data_dir.join("cas.db"), &data_dir.join("cas"))?;
        Ok(Self {
            operational: Mutex::new(operational),
            operational_path,
            cas,
        })
    }

    fn locked(&self) -> KataResult<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.operational
            .lock()
            .map_err(|error| refused(&format!("operational read handle is poisoned: {error}")))
    }

    /// The `artifacts` row's claim about `artifact`, or `None` when the plane holds no
    /// row for it.
    fn artifact_claim(
        &self,
        artifact: ArtifactId,
    ) -> KataResult<Option<(ObjectClaim, ArtifactPrivacy)>> {
        let connection = self.locked()?;
        let row: Option<(Vec<u8>, i64, String)> = connection
            .query_row(
                "SELECT object_id, size_bytes, privacy FROM artifacts WHERE artifact_id = ?1",
                rusqlite::params![artifact.0.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional_row()?;
        let Some((object, size_bytes, privacy)) = row else {
            return Ok(None);
        };
        let object = object_id_from(&object, "artifacts.object_id")?;
        let size_bytes = u64::try_from(size_bytes)
            .map_err(|_| refused("artifacts.size_bytes is negative, which is not a length"))?;
        let privacy = match privacy.as_str() {
            "public" => ArtifactPrivacy::Public,
            "private" => ArtifactPrivacy::Private,
            other => {
                return Err(refused(&format!(
                    "artifacts.privacy is `{other}`, which is neither `public` nor `private`"
                )));
            }
        };
        Ok(Some((ObjectClaim { object, size_bytes }, privacy)))
    }
}

/// `query_row` + `optional`, with this module's refusal wrapped around the error.
trait OptionalRow<T> {
    fn optional_row(self) -> KataResult<Option<T>>;
}

impl<T> OptionalRow<T> for Result<T, rusqlite::Error> {
    fn optional_row(self) -> KataResult<Option<T>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(refused(&format!("read the operational plane: {error}"))),
        }
    }
}

fn object_id_from(bytes: &[u8], column: &str) -> KataResult<ObjectId> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| refused(&format!("{column} is not 32 bytes")))?;
    Ok(kata_types::primitives::FixedBytes(array))
}

impl EnvironmentIndex for LocalPlaneIndex {
    fn environment_claim(
        &self,
        environment: EnvironmentId,
    ) -> KataResult<Option<EnvironmentClaim>> {
        let connection = self.locked()?;
        let row: Option<(Vec<u8>, Option<i64>, Option<i64>)> = connection
            .query_row(
                "SELECT manifest_object_id, root_promoted_at_ms, released_at_ms \
                   FROM nix_environments WHERE environment_id = ?1",
                rusqlite::params![environment.0.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional_row()?;
        let Some((object, promoted, released)) = row else {
            return Ok(None);
        };
        let object = object_id_from(&object, "nix_environments.manifest_object_id")?;
        // The LENGTH is the CAS's own record, not the environment row's: `nix_environments`
        // carries no size column, and inventing one here would be a second answer to "how
        // long is that object". A wrong length cannot pass the identity check below it —
        // the artifact id folds the size.
        let size_bytes = self.cas.recorded_size(object)?.ok_or_else(|| {
            refused(&format!(
                "environment_manifest_unreadable: environment {}'s manifest object {object} has \
                 no row in this worker's content store, so there is no length to read it at",
                environment.0
            ))
        })?;
        Ok(Some(EnvironmentClaim {
            manifest: ObjectClaim { object, size_bytes },
            released: released.is_some(),
            root_promoted: promoted.is_some(),
        }))
    }
}

impl TreeResolver for LocalPlaneIndex {
    fn tree_reference(&self, artifact: ArtifactId) -> KataResult<ArtifactRef> {
        let (claim, privacy) = self.artifact_claim(artifact)?.ok_or_else(|| {
            refused(&format!(
                "artifact_unknown_to_this_worker: this worker's plane holds no artifacts row \
                 for {}, which the capsule maps. The artifact was declared on the main that \
                 authorized this attempt and an artifacts row is never deleted, so this worker \
                 reads a different data directory",
                artifact.0
            ))
        })?;
        // THE SAME TWO-CARRIER CHECK the environment gets, for the same reason.
        let reference = ArtifactRef::new(claim.object, claim.size_bytes, privacy);
        if reference.id() != artifact {
            return Err(refused(&format!(
                "artifact_identity_mismatch: the capsule maps artifact {wanted}, and the row \
                 pointing at object {object} recomputes to {found}. An artifact id folds the \
                 object, its length and its privacy, so this row names DIFFERENT bytes than the \
                 capsule committed to",
                wanted = artifact.0,
                object = claim.object,
                found = reference.id().0,
            )));
        }
        Ok(reference)
    }

    fn tree_manifest(&self, artifact: ArtifactId) -> KataResult<TreeManifest> {
        let reference = self.tree_reference(artifact)?;
        let bytes = self
            .cas
            .read_verified(
                reference.object_id(),
                reference.size_bytes(),
                TreeManifest::MAXIMUM_ENCODED_BYTES,
            )
            .map_err(|error| {
                refused(&format!(
                    "artifact_manifest_unreadable: artifact {}'s object {} ({} bytes claimed) is \
                     not readable from this worker's content store: {error}",
                    artifact.0,
                    reference.object_id(),
                    reference.size_bytes()
                ))
            })?;
        serde_json::from_slice::<TreeManifest>(&bytes).map_err(|error| {
            refused(&format!(
                "artifact_manifest_unreadable: artifact {}'s object {} does not decode as a tree \
                 manifest: {error}",
                artifact.0,
                reference.object_id()
            ))
        })
    }
}

impl BlobSource for LocalPlaneIndex {
    fn read_verified(
        &self,
        object: ObjectId,
        expected_size: u64,
        maximum: u64,
    ) -> KataResult<Vec<u8>> {
        self.cas.read_verified(object, expected_size, maximum)
    }
}
