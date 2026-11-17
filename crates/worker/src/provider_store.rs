//! **An external provider is identified by CONTENT.**
//!
//! Node configuration names a content ADDRESS; this module resolves it through a
//! by-hash store to a HOST path, and
//! [`crate::provider_supervisor::ProviderSupervisor`] spawns exactly that path.
//! There is no `PATH` resolution, and no other location-shaped alternative
//! ("next to the kata binary" and its relatives), which would be the same
//! failure one step weaker: a path is a NAME for whatever bytes currently sit
//! there.
//!
//! # The store is SELF-DESCRIBING, and that is its whole trust basis
//!
//! A store entry's DIRECTORY NAME IS THE CONTENT HASH OF ITS CONTENTS — the
//! content hash is paid ONCE, at provisioning. So "are these
//! the bytes the address names?" is a question about the bytes themselves:
//! [`ProviderStore::resolve`] re-derives the entry's hash from its contents on
//! every resolution and refuses an entry whose name and contents disagree. A memo
//! keyed on anything the owning uid can forge would be a memo an attacker chooses,
//! so nothing is cached. The trust basis is EARNED per resolution rather than
//! asserted by location; an operator may site the store wherever they like.
//!
//! What the store is NOT: acquisition (fetching, signatures and GC across
//! generations are not implemented — the operator provisions bytes they
//! already control and kata copies them), and provenance (an
//! address proves the bytes run are the bytes hashed, not where they came from).
//!
//! **A provider is never MOUNTED.** It is the process kata spawns carrying the
//! kata seccomp floor — `provider_command_prefix` makes the provider binary the prefix's own
//! `program` — and the store's entries are resolved to HOST paths only.
//!
//! # TWO DESIGN JOINTS, each with what REVERSING it costs
//!
//! ### Joint 1 — the store provisions DIRECTORIES; a provider is one executable
//!
//! **The store provisions a DIRECTORY holding `kata-provider-<name>`.**
//! [`ProviderStore::provision`] refuses a non-directory by name and
//! [`ProviderStore::resolve`] re-hashes a directory. The alternative was a
//! single-file store mode with its own verification semantics, i.e. a second
//! answer to *"do these bytes hash to their own name"*. A provider entry may also
//! legitimately hold adjacent files (`kata-oci-hook`, `ip` —
//! [`ResolvedProvider::member`]), which a file-shaped entry could not.
//!
//! *Reversing costs*: [`ProviderStore::provision`] and
//! [`ProviderStore::resolve`] change shape, the entry layout changes, and every
//! provisioned entry must be re-provisioned — the address rotates. Nothing
//! outside this module and its refusal messages moves.
//!
//! ### Joint 2 — the declared value stays a NAME; a SECOND value carries the address
//!
//! See [`crate::execution_route::ExternalProviderDeclaration`]; the joint is
//! recorded there because that is where the parser lives.
//!
//! # The tree hash is a DURABLE format
//!
//! [`STORE_TREE_DOMAIN`] and the manifest [`hash_tree`] folds are part of every
//! address an operator exports. Changing either rotates every provisioned
//! provider's address, and a node whose `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS`
//! no longer resolves is refused rather than handed new bytes — so a change to
//! either is a format change that needs every provider re-provisioned.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_types::error::{KataError, KataResult};
use kata_types::sandbox::is_blake3_hex;

use crate::execution_route::{
    EXTERNAL_PROVIDER_ADDRESS_ENV, EXTERNAL_PROVIDER_ENV, ExternalProviderAddress,
    ExternalProviderDeclaration,
};
use crate::provider_supervisor::PROVIDER_BINARY_PREFIX;

/// Domain tag for the store's tree content hash, so it can never collide with
/// any other blake3 digest in the workspace.
///
/// It is folded into every address the store mints, so changing it rotates every
/// provisioned provider's address — see the module docs.
const STORE_TREE_DOMAIN: &str = "kata.provider.store.tree.v1";

/// Staging-directory prefix inside the store root. Leading `.` and a ULID so a
/// concurrent provision of the same source cannot collide, and so a crashed
/// provision leaves something an operator can identify and delete rather than a
/// half-populated `<hex>` that would then fail verification forever.
const STAGING_PREFIX: &str = ".staging-";

/// The env key naming THIS NODE's by-hash EXTERNAL PROVIDER store root.
///
/// UNSET means this node holds no provider, which is not an error until an
/// operator declares one — and then it is a REFUSAL naming this key, never a
/// fallback to `PATH`, and never a fallback to anything else.
///
/// A blank value is ABSENT, the same reading
/// [`crate::execution_route::declared_external_provider`] gives its own keys.
pub const EXTERNAL_PROVIDER_STORE_ENV: &str = "KATA_EXTERNAL_PROVIDER_STORE";

/// The node-configuration keys that together declare THIS NODE's external
/// provider: the store root, the provider name and its content address.
///
/// The one list of them. `kata host setup` writes exactly these into the
/// operator's `.env` (through [`ProvisionedProvider::node_environment`]), and
/// `kata service install` copies exactly these into the installed main's
/// environment snapshot — the service never reads `.env` — so the set one writes
/// and the set the other carries cannot drift apart.
pub const NODE_PROVIDER_ENV_KEYS: [&str; 3] = [
    EXTERNAL_PROVIDER_STORE_ENV,
    EXTERNAL_PROVIDER_ENV,
    EXTERNAL_PROVIDER_ADDRESS_ENV,
];

/// The provider store root THIS PROCESS's environment declares, or `None`.
///
/// The ONE reader of [`EXTERNAL_PROVIDER_STORE_ENV`], so the resolver and the
/// lever report cannot disagree about whether this node has a provider store.
///
/// # Errors
///
/// Exactly a value that is not UTF-8, refused naming the variable and never
/// the value (`crate::execution_route::declared_text`): a declaration kata
/// cannot read is not an undeclared one.
pub fn declared_provider_store_root() -> KataResult<Option<PathBuf>> {
    Ok(crate::execution_route::declared_text(EXTERNAL_PROVIDER_STORE_ENV)?.map(PathBuf::from))
}

/// What [`ProviderStore::provision`] put in the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionedProvider {
    /// The minted address — the value that goes in
    /// [`EXTERNAL_PROVIDER_ADDRESS_ENV`].
    pub address: ExternalProviderAddress,
    /// The provider NAME this entry answers for — the value that goes in
    /// [`EXTERNAL_PROVIDER_ENV`].
    pub name: String,
    /// The store entry's absolute host path, `<root>/<hex>`.
    pub entry: PathBuf,
    /// The provider executable inside it, `<entry>/kata-provider-<name>`.
    pub binary: PathBuf,
    /// Regular files in the entry.
    pub files: usize,
    /// Total bytes of regular-file content in the entry.
    pub bytes: u64,
}

impl ProvisionedProvider {
    /// The [`NODE_PROVIDER_ENV_KEYS`] declaration that routes this node to this
    /// provider, `root` being the store it was provisioned into: each key paired
    /// with its value, in the list's order.
    #[must_use]
    pub fn node_environment(&self, root: &Path) -> [(&'static str, String); 3] {
        let [store, name, address] = NODE_PROVIDER_ENV_KEYS;
        [
            (store, root.display().to_string()),
            (name, self.name.clone()),
            (address, self.address.to_string()),
        ]
    }

    /// The three lines an operator exports to route this node to this provider.
    ///
    /// Rendered from [`Self::node_environment`], never typed out, so an install
    /// instruction and the key it names cannot drift apart. This is the whole
    /// operator-facing install story and it is generated rather than documented:
    /// a README can go stale, and `kata sandbox install-external-provider` prints
    /// this.
    #[must_use]
    pub fn operator_exports(&self, root: &Path) -> String {
        self.node_environment(root)
            .iter()
            .map(|(key, value)| format!("export {key}={value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// A provider RESOLVED to bytes: the host path kata will spawn, and the address
/// whose contents were RE-DERIVED to get there.
///
/// # This is a MEASUREMENT, not a declaration
///
/// [`Self::address`] is not the operator's string echoed back. It is the hex
/// [`ProviderStore::resolve`] re-derived from the entry's own contents and found
/// equal to the entry's name — so a value of this type cannot exist for a store entry
/// whose bytes were replaced, and the binary it names is an observation, not an
/// echo (the claimed/measured cut, applied to an identity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedProvider {
    name: String,
    address: ExternalProviderAddress,
    entry: PathBuf,
    binary: PathBuf,
}

impl ResolvedProvider {
    /// The provider NAME this resolution answers for — what the handshake
    /// checks against the certificate.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The VERIFIED content address of the entry the binary came out of.
    #[must_use]
    pub const fn address(&self) -> &ExternalProviderAddress {
        &self.address
    }

    /// The store entry, `<root>/<hex>` — a HOST path. Never a guest path: see
    /// the module docs.
    #[must_use]
    pub fn entry(&self) -> &Path {
        &self.entry
    }

    /// The executable kata spawns.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// A second REGULAR FILE inside the verified entry — `kata-oci-hook`, `ip`
    /// — or `None` when the entry holds no such member. The entry's content
    /// address covers its whole directory tree (the closure hash the resolve
    /// re-verified), so a member needs no second pin: its bytes are already the
    /// bytes the address names. A member that is not a regular file — a
    /// directory, a symlink — answers `None` rather than a path whose exec
    /// would mean something else.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<PathBuf> {
        let candidate = self.entry.join(name);
        // `symlink_metadata` and not `is_file`: the doc above promises a SYMLINK
        // answers `None`, and `is_file` follows the link — which would let an
        // entry smuggle a member its content hash never covered.
        candidate
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_file())
            .then_some(candidate)
    }

    /// The entry's `toolhost/` DIRECTORY, which a nanocode agent capsule binds
    /// read-only at `/.kata` as the directory its init comes from, once it is
    /// proven to hold exactly one regular file, `kata-toolhost`, that its owner
    /// may execute.
    ///
    /// A directory and not a member file because the bind is a directory bind:
    /// the provider creates directory mount points only, and binding this
    /// directory is what keeps every other file of the entry (the provider, the
    /// hook, `ip`) out of the guest. So the directory's contents ARE what the
    /// guest sees, and they are checked as such.
    ///
    /// # Refused set
    ///
    /// Each refusal is `toolhost_unavailable`, naming which of these it is:
    /// `toolhost` absent; `toolhost` not a real directory (judged by
    /// `symlink_metadata`, so a symlink is refused rather than followed: a link
    /// would bind bytes the entry's address never covered); `toolhost` that
    /// cannot be listed; a listing that is anything but exactly the one name
    /// `kata-toolhost` (an extra file would be visible to every agent capsule,
    /// and an empty directory is a launch that cannot exec); `kata-toolhost`
    /// whose metadata cannot be read; `kata-toolhost` not a regular file (a
    /// symlink or a directory); and `kata-toolhost` without its OWNER execute
    /// bit (the container's init runs as the entry's owner, so a group or other
    /// bit alone would still not let it exec).
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which refused and the recourse.
    pub fn toolhost_dir(&self) -> KataResult<PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = self.entry.join(TOOLHOST_DIRECTORY);
        let program = dir.join(TOOLHOST_PROGRAM);
        let refuse = |why: String| {
            KataError::Validation(format!(
                "sandbox: toolhost_unavailable: the provider entry `{entry}` cannot supply a \
                 nanocode agent capsule's tool host: {why}. The tool host is the capsule's \
                 init, bound read-only at `/.kata` from the entry's `{TOOLHOST_DIRECTORY}/` \
                 directory, which must hold exactly one regular file `{TOOLHOST_PROGRAM}` its \
                 owner may execute. Re-provision the provider from a source directory holding \
                 `{TOOLHOST_DIRECTORY}/{TOOLHOST_PROGRAM}` (`kata sandbox \
                 install-external-provider`) and export the address it prints.",
                entry = self.entry.display(),
            ))
        };
        match dir.symlink_metadata() {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                return Err(refuse(format!(
                    "`{TOOLHOST_DIRECTORY}` is not a directory (a symlink is refused, never \
                     followed)"
                )));
            }
            Err(error) => {
                return Err(refuse(format!(
                    "`{TOOLHOST_DIRECTORY}` is absent ({error})"
                )));
            }
        }
        let names = std::fs::read_dir(&dir)
            .and_then(|entries| {
                entries
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<std::io::Result<Vec<std::ffi::OsString>>>()
            })
            .map_err(|error| {
                refuse(format!("`{TOOLHOST_DIRECTORY}` cannot be listed ({error})"))
            })?;
        if names != [std::ffi::OsStr::new(TOOLHOST_PROGRAM)] {
            let mut names = names;
            names.sort();
            return Err(refuse(format!(
                "`{TOOLHOST_DIRECTORY}/` holds {names:?}, not exactly [{TOOLHOST_PROGRAM:?}]; \
                 every file in it is visible to the guest"
            )));
        }
        let meta = program.symlink_metadata().map_err(|error| {
            refuse(format!(
                "`{TOOLHOST_DIRECTORY}/{TOOLHOST_PROGRAM}` cannot be read ({error})"
            ))
        })?;
        if !meta.file_type().is_file() {
            return Err(refuse(format!(
                "`{TOOLHOST_DIRECTORY}/{TOOLHOST_PROGRAM}` is not a regular file (a symlink is \
                 refused, never followed)"
            )));
        }
        if meta.permissions().mode() & 0o100 == 0 {
            return Err(refuse(format!(
                "`{TOOLHOST_DIRECTORY}/{TOOLHOST_PROGRAM}` has no owner execute bit (mode \
                 {:o}), so the capsule's init could not exec it",
                meta.permissions().mode() & 0o7777
            )));
        }
        Ok(dir)
    }
}

/// The provider entry's subdirectory holding a nanocode agent capsule's tool
/// host; see [`ResolvedProvider::toolhost_dir`].
pub const TOOLHOST_DIRECTORY: &str = "toolhost";
/// The one file [`TOOLHOST_DIRECTORY`] holds.
pub const TOOLHOST_PROGRAM: &str = "kata-toolhost";

/// A by-hash provisioning store for external providers, rooted at an
/// operator-chosen directory.
///
/// The handle is needed to PROVISION and to RESOLVE. Resolution needs it because
/// a provider arrives as an ADDRESS and nothing else, so `<root>/<hex>` is the map
/// it must be looked up in.
#[derive(Clone, Debug)]
pub struct ProviderStore {
    root: PathBuf,
}

impl ProviderStore {
    /// A provider store rooted at `root`. The directory is created on the first
    /// [`Self::provision`], not here — constructing a handle must not mutate the
    /// operator's filesystem.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path a given content hash occupies in this store.
    #[must_use]
    pub fn entry_path(&self, hex: &str) -> PathBuf {
        self.root.join(hex)
    }

    /// Copy `source` into the store, hash the COPY, seal it, publish it at
    /// `<root>/<hex>`, and mint the address that names it.
    ///
    /// `source` must be a DIRECTORY holding `kata-provider-<name>` — joint 1.
    ///
    /// # Why the hash is over the COPY and not the source
    ///
    /// The address must describe the bytes that will be SPAWNED, and those are
    /// the copy's. Hashing the source and then copying leaves a window in which
    /// the copy can differ — a source mutated mid-copy, a short read, a full
    /// disk — and the entry would then carry a name its contents do not produce,
    /// which is the one thing this store exists to make impossible.
    ///
    /// # Idempotent
    ///
    /// Provisioning byte-identical bytes twice yields the same `<hex>`, and the
    /// second call observes the existing entry and discards its staging copy.
    ///
    /// # Durability
    ///
    /// Success follows synchronization of the sealed files and directories,
    /// publication, and synchronization of the store directory and its ancestors.
    /// An existing entry is verified and synchronized too: it may be the residue
    /// of a publication whose final sync failed. A failed final sync leaves that
    /// entry intact and returns an error; retry can finish its durability boundary.
    /// Verification certifies bytes and executable bits, not protection against
    /// modification by their owning uid.
    ///
    /// # Errors
    ///
    /// * `source` is not a directory, or holds no `kata-provider-<name>`;
    /// * `name` is not a provider name — checked through
    ///   [`ExternalProviderDeclaration`]'s own parser, so a store can never hold
    ///   an entry under a name the route would refuse;
    /// * the tree carries a node type the store does not represent (device,
    ///   socket, fifo) — see [`hash_tree`];
    /// * any filesystem operation fails.
    pub fn provision(&self, name: &str, source: &Path) -> KataResult<ProvisionedProvider> {
        self.provision_with_members(name, source, &[])
    }

    /// [`Self::provision`], with each `(member, path)` in `members` copied into
    /// the entry beside `source`'s contents — a member the operator's install
    /// DECLARES by path rather than ships inside the source directory (`kata
    /// host setup` declares the iproute2 `ip` by its Nix store path).
    ///
    /// The entry is the one `source` would provision had it held each member
    /// itself: same file set, same bytes, same executable bits, so the same
    /// address. Each member is checked before anything is staged:
    ///
    /// * `member` is one plain file name — no separator, not `.` or `..`;
    /// * `source` does not already hold `member` — two answers for one file
    ///   would make the entry depend on which won;
    /// * `path` is a REGULAR file. A symlink is refused, never followed: the
    ///   entry would hold either a link (not bytes the store owns) or bytes the
    ///   declaration never named. A caller that declares a link resolves it
    ///   first and passes the file.
    ///
    /// # Errors
    ///
    /// Everything [`Self::provision`] refuses, and each member check above.
    pub fn provision_with_members(
        &self,
        name: &str,
        source: &Path,
        members: &[(&str, &Path)],
    ) -> KataResult<ProvisionedProvider> {
        let name = ExternalProviderDeclaration::parse_name(name)?;
        if !source.is_dir() {
            return Err(KataError::Config(format!(
                "provider store: `{source}` is not a directory. A provider is provisioned as the \
                 DIRECTORY holding its executable `{PROVIDER_BINARY_PREFIX}{name}`, not as the \
                 executable itself — the entry's directory name becomes the content hash of its \
                 contents, which is the identity `{EXTERNAL_PROVIDER_ADDRESS_ENV}` names. Put the \
                 binary in a directory of its own and provision that.",
                source = source.display(),
            )));
        }
        let expected = format!("{PROVIDER_BINARY_PREFIX}{name}");
        if !source.join(&expected).is_file() {
            return Err(KataError::Config(format!(
                "provider store: `{source}` holds no `{expected}`, so it is not the provider \
                 `{name}`. A provider named `x` is the program `{PROVIDER_BINARY_PREFIX}x` inside \
                 its store entry — that convention is what lets one entry answer for a named \
                 provider without a second knob pointing at a file. Directory holds: {listing}",
                source = source.display(),
                listing = list_entry(source),
            )));
        }
        for &(member, path) in members {
            check_declared_member(source, member, path)?;
        }

        std::fs::create_dir_all(&self.root).map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot create the store root `{}`: {e}",
                self.root.display()
            ))
        })?;
        let staging = self
            .root
            .join(format!("{STAGING_PREFIX}{}", ulid::Ulid::new()));
        // A staging failure must not leave the directory behind: the operator
        // would have no way to tell it from a provision still in flight.
        let digest = match self.stage_and_publish(source, members, &staging) {
            Ok(digest) => digest,
            Err(error) => {
                let _ = unseal_tree(&staging);
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        let entry = self.entry_path(&digest.hex);
        Ok(ProvisionedProvider {
            binary: entry.join(&expected),
            entry,
            address: ExternalProviderAddress::from_verified_hex(&digest.hex),
            name,
            files: digest.files,
            bytes: digest.bytes,
        })
    }

    /// The body of [`Self::provision`] after its source checks, split out so the
    /// caller owns the staging-directory cleanup on every error path.
    fn stage_and_publish(
        &self,
        source: &Path,
        members: &[(&str, &Path)],
        staging: &Path,
    ) -> KataResult<TreeDigest> {
        copy_tree(source, staging)?;
        for &(member, path) in members {
            copy_declared_member(member, path, &staging.join(member))?;
        }
        let digest = hash_tree(staging)?;
        let published = self.entry_path(&digest.hex);

        if published.exists() {
            finish_existing_publication(&published, staging)?;
        } else {
            seal_tree(staging)?;
            sync_tree(staging)?;
            match publish_directory(staging, &published) {
                Ok(()) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        || error.raw_os_error() == Some(libc::ENOTEMPTY) =>
                {
                    // Another provisioner won the rename. Its directory is not
                    // evidence of durability until this caller verifies and syncs it.
                    finish_existing_publication(&published, staging)?;
                }
                Err(error) => {
                    return Err(KataError::Config(format!(
                        "provider store: cannot publish `{}` as `{}`: {error}",
                        staging.display(),
                        published.display()
                    )));
                }
            }
        }

        // create_dir_all may have introduced several ancestors. Sync child
        // before parent, including existing ancestors on retry after a failed
        // sync: existence alone cannot tell which directory entries are durable.
        let root = self.root.canonicalize().map_err(|error| {
            KataError::Config(format!(
                "provider store: cannot resolve store directory `{}` for synchronization: \
                 {error}",
                self.root.display()
            ))
        })?;
        for directory in root.ancestors() {
            sync_path(directory)?;
        }
        Ok(digest)
    }

    /// **Resolve a DECLARATION to bytes** — identification by content's central
    /// operation.
    ///
    /// `<root>/<hex>` is opened, its contents are re-hashed, and the hash must
    /// equal the entry's own name. Only then is `kata-provider-<name>` inside it
    /// located.
    ///
    /// # Errors
    ///
    /// Every arm names the key that produced the value it could not use and an
    /// action the operator can take. **Never a fallback** — not to `PATH`, not
    /// to a location: an operator who named a provider asked for that provider.
    pub fn resolve(
        &self,
        declaration: &ExternalProviderDeclaration,
    ) -> KataResult<ResolvedProvider> {
        let hex = declaration.address().hex();
        let entry = self.entry_path(hex);
        let verified = match verify_store_entry(&entry) {
            StoreVerdict::Verified(observed) => observed,
            StoreVerdict::Mismatch { claimed, observed } => {
                return Err(KataError::Validation(format!(
                    "sandbox: this node declares the EXTERNAL provider `{name}` at \
                     `{EXTERNAL_PROVIDER_ADDRESS_ENV}={address}`, and the store entry `{entry}` \
                     does NOT hash to its own name: it claims `{claimed}` and its contents produce \
                     `{observed}`. Those bytes are not the bytes the address names, and running \
                     them would be exactly the substitution content addressing exists to refuse. \
                     Nothing was spawned. Re-provision the provider (`kata sandbox \
                     install-external-provider`), which mints a fresh address, and set \
                     `{EXTERNAL_PROVIDER_ADDRESS_ENV}` to it.",
                    name = declaration.name(),
                    address = declaration.address(),
                    entry = entry.display(),
                )));
            }
            StoreVerdict::Unreadable(why) => {
                return Err(KataError::Validation(format!(
                    "sandbox: this node declares the EXTERNAL provider `{name}` at \
                     `{EXTERNAL_PROVIDER_ADDRESS_ENV}={address}`, and its store entry `{entry}` \
                     could not be read: {why} This node's provider store root is \
                     `{EXTERNAL_PROVIDER_STORE_ENV}={root}`. Install the provider there with \
                     `kata sandbox install-external-provider --name {name} <directory holding \
                     {PROVIDER_BINARY_PREFIX}{name}>`, then export the address it prints. \
                     Refusing rather than searching anywhere else: a provider found by looking \
                     around is a provider identified by LOCATION.",
                    name = declaration.name(),
                    address = declaration.address(),
                    entry = entry.display(),
                    root = self.root.display(),
                )));
            }
            StoreVerdict::NotStoreShaped => {
                // Unreachable while `ExternalProviderAddress` admits only 64
                // lowercase hex — `entry_path` joins exactly that, so
                // `file_name()` IS a blake3 hex. Reported rather than
                // `unreachable!()`: a build in which the two disagree should say
                // so, not abort.
                return Err(KataError::Validation(format!(
                    "sandbox: BUILD INCONSISTENCY — the store entry `{entry}` for provider \
                     `{name}` is not store-shaped, but `{EXTERNAL_PROVIDER_ADDRESS_ENV}` admits \
                     only a 64-character blake3 hex. `ExternalProviderAddress` and \
                     `verify_store_entry` disagree about what an address looks like.",
                    entry = entry.display(),
                    name = declaration.name(),
                )));
            }
        };

        let expected = format!("{PROVIDER_BINARY_PREFIX}{name}", name = declaration.name());
        let binary = entry.join(&expected);
        if !binary.is_file() {
            return Err(KataError::Validation(format!(
                "sandbox: the store entry `{entry}` VERIFIES — its contents hash to its own name — \
                 but it holds no `{expected}`, so it is not the provider `{name}` that \
                 `{EXTERNAL_PROVIDER_ENV}` declares. The address and the name are two node-\
                 configuration values and they name one thing between them: the address picks the \
                 ENTRY, the name picks the executable inside it. Entry holds: {listing}. Either \
                 correct `{EXTERNAL_PROVIDER_ENV}`, or provision the provider you meant and set \
                 `{EXTERNAL_PROVIDER_ADDRESS_ENV}` to the address that prints.",
                entry = entry.display(),
                name = declaration.name(),
                listing = list_entry(&entry),
            )));
        }

        Ok(ResolvedProvider {
            name: declaration.name().to_owned(),
            address: ExternalProviderAddress::from_verified_hex(&verified),
            entry,
            binary,
        })
    }
}

/// The entry's own contents, for a refusal that has to say what the operator
/// actually provisioned.
///
/// A refusal naming only what it wanted is a refusal an operator answers by
/// guessing. Bounded at eight names: an entry with a thousand files is a
/// different mistake and a thousand-line error message is not how to report it.
fn list_entry(dir: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return "(unreadable)".to_owned();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    if names.is_empty() {
        return "(nothing)".to_owned();
    }
    let total = names.len();
    names.truncate(8);
    let listed = names.join(", ");
    if total > 8 {
        format!("{listed} (+{} more)", total - 8)
    } else {
        listed
    }
}

// ---------------------------------------------------------------------------
// The store's mechanism: verify, hash, copy, seal
// ---------------------------------------------------------------------------

/// What [`verify_store_entry`] found at an entry path.
///
/// Four outcomes rather than a `bool`, because "not store-shaped", "does not
/// verify" and "cannot be read" are different refusals an operator acts on
/// differently, and [`ProviderStore::resolve`] names each by its own cause.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StoreVerdict {
    /// The path's final component is not a blake3 hex, so it never claimed to be
    /// a store entry.
    NotStoreShaped,
    /// The entry's contents hash to its own name.
    Verified(String),
    /// The entry's contents do NOT hash to its own name. Names both hexes.
    Mismatch {
        /// The hex the entry's DIRECTORY NAME claims.
        claimed: String,
        /// The hex the entry's CONTENTS actually produce.
        observed: String,
    },
    /// The entry could not be read at all — absent, unreadable, or holding a
    /// node type the store does not carry.
    Unreadable(String),
}

fn finish_existing_publication(published: &Path, staging: &Path) -> KataResult<()> {
    let verdict = verify_store_entry(published);
    if !matches!(verdict, StoreVerdict::Verified(_)) {
        return Err(KataError::Config(format!(
            "provider store: `{}` already exists and does NOT verify ({verdict:?}). \
             Refusing to publish over it — an entry whose name and contents disagree \
             is exactly what this store exists to make impossible, and overwriting it \
             would destroy the evidence. Remove it by hand (its directories are mode \
             0500, so `chmod -R u+w` first) and re-provision.",
            published.display()
        )));
    }
    sync_tree(published)?;
    unseal_tree(staging)?;
    std::fs::remove_dir_all(staging).map_err(|error| {
        KataError::Config(format!(
            "provider store: cannot remove the staging copy `{}`: {error}",
            staging.display()
        ))
    })
}

/// `renameat2(RENAME_NOREPLACE)` through rustix's raw syscall, which every Linux libc
/// target reaches — nix 0.28 offers `renameat2` only on glibc, and the factory smoke's
/// in-capsule `kata` is a static musl build of this tree.
#[cfg(target_os = "linux")]
fn publish_directory(staging: &Path, published: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        published,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

// Preserve the existing non-Linux path; exclusive rename certification is Linux-only.
#[cfg(not(target_os = "linux"))]
fn publish_directory(staging: &Path, published: &Path) -> std::io::Result<()> {
    std::fs::rename(staging, published)
}

/// Synchronize sealed regular files before directories, deepest directory first.
/// Symlink entries are persisted by their parent directory; never follow their
/// targets, which may deliberately name paths outside this tree for whole roots.
fn sync_tree(root: &Path) -> KataResult<()> {
    let entries = std::fs::read_dir(root).map_err(|error| {
        KataError::Config(format!(
            "provider store: cannot read `{}` for synchronization: {error}",
            root.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            KataError::Config(format!(
                "provider store: cannot read an entry of `{}` for synchronization: {error}",
                root.display()
            ))
        })?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| {
            KataError::Config(format!(
                "provider store: cannot stat `{}` for synchronization: {error}",
                path.display()
            ))
        })?;
        if kind.is_dir() {
            sync_tree(&path)?;
        } else if kind.is_file() {
            sync_path(&path)?;
        } else if !kind.is_symlink() {
            return Err(KataError::Config(format!(
                "provider store: unsupported node `{}` during synchronization",
                path.display()
            )));
        }
    }
    sync_path(root)
}

fn sync_path(path: &Path) -> KataResult<()> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            KataError::Config(format!(
                "provider store: cannot synchronize `{}`: {error}",
                path.display()
            ))
        })
}

/// A tree's content hash plus what it covers, so a caller can report the cost of
/// the guarantee rather than assert it.
#[derive(Debug, Clone)]
struct TreeDigest {
    /// blake3 hex over the whole tree — 64 lowercase chars.
    hex: String,
    /// Regular files hashed.
    files: usize,
    /// Total regular-file bytes hashed.
    bytes: u64,
}

/// Is `path` a self-verifying by-hash store entry?
///
/// # It reads the BYTES, every resolution
///
/// A length-preserving substitution is invisible to any check cheaper than
/// reading the content — a `stat` manifest over an entry would certify the
/// substituted bytes. So this hashes the file contents, at every resolution
/// rather than once per process: a memo keyed on anything the same uid can forge
/// is a memo an attacker chooses.
///
/// # What a verdict means
///
/// * [`StoreVerdict::NotStoreShaped`] — the final path component is not 64
///   lowercase hex chars, so nothing was opened.
/// * [`StoreVerdict::Verified`] — the contents hash to the name.
/// * [`StoreVerdict::Mismatch`] — they do not. The caller REFUSES.
/// * [`StoreVerdict::Unreadable`] — absent, unreadable, or carrying a node type
///   the store does not represent. The caller REFUSES; an entry that cannot be
///   read is not an entry that can be trusted.
#[must_use]
fn verify_store_entry(path: &Path) -> StoreVerdict {
    let Some(claimed) = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| is_blake3_hex(n))
    else {
        return StoreVerdict::NotStoreShaped;
    };
    match hash_tree(path) {
        Ok(digest) if digest.hex == claimed => StoreVerdict::Verified(digest.hex),
        Ok(digest) => StoreVerdict::Mismatch {
            claimed: claimed.to_string(),
            observed: digest.hex,
        },
        Err(e) => StoreVerdict::Unreadable(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tree hashing
// ---------------------------------------------------------------------------

/// One entry in the deterministic tree manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Dir,
    File,
    Symlink,
}

impl NodeKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Dir => 1,
            Self::File => 2,
            Self::Symlink => 3,
        }
    }
}

/// Content-hash a directory tree deterministically.
///
/// # What is folded, and what is deliberately not
///
/// Folded, per entry in **sorted relative-path order** (`BTreeMap`, so
/// `read_dir`'s arbitrary order cannot reach the digest):
///
/// * the relative path bytes, length-prefixed;
/// * the node kind (dir / file / symlink);
/// * for a FILE: the executable bit, the byte length, and **the file's whole
///   contents**;
/// * for a SYMLINK: the link target bytes. Not followed — a symlink is part of an
///   entry's shape, and following it would both double-count and escape the
///   entry.
///
/// NOT folded, each for a reason:
///
/// * **mtime / atime / ctime** — `cp -a` preserves them and a plain `cp` does
///   not, so folding them would make one tree hash to two addresses depending on
///   how it was copied. Content is content.
/// * **uid / gid** — the store is provisioned by whoever runs kata; the same
///   bytes under two accounts are the same entry.
/// * **the full mode** — only the executable bit, because that is the only mode
///   bit that changes what the entry DOES, and [`seal_tree`] deliberately
///   rewrites the rest. Folding the sealed mode would make a store entry's hash
///   depend on the sealing that happens after it is computed.
/// * **hard-link structure** — invisible without inode bookkeeping that would
///   make the digest depend on the filesystem rather than the bytes.
///
/// # Errors
///
/// A device, socket, or fifo inside the tree is a REFUSAL, not a skip: silently
/// ignoring it would leave a node inside the entry that no address covers.
fn hash_tree(root: &Path) -> KataResult<TreeDigest> {
    let mut manifest: BTreeMap<PathBuf, (NodeKind, u64)> = BTreeMap::new();
    collect_tree(root, Path::new(""), &mut manifest)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(STORE_TREE_DOMAIN.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(&(manifest.len() as u64).to_le_bytes());

    let mut files = 0usize;
    let mut bytes = 0u64;

    for (rel, (kind, exec_bit)) in &manifest {
        let rel_bytes = rel.as_os_str().as_encoded_bytes();
        hasher.update(&(rel_bytes.len() as u64).to_le_bytes());
        hasher.update(rel_bytes);
        hasher.update(&[kind.tag()]);
        let abs = root.join(rel);
        match kind {
            NodeKind::Dir => {}
            NodeKind::Symlink => {
                let target = std::fs::read_link(&abs).map_err(|e| {
                    KataError::Config(format!(
                        "provider store: cannot read symlink `{}`: {e}",
                        abs.display()
                    ))
                })?;
                let target_bytes = target.as_os_str().as_encoded_bytes();
                hasher.update(&(target_bytes.len() as u64).to_le_bytes());
                hasher.update(target_bytes);
            }
            NodeKind::File => {
                hasher.update(&[u8::try_from(*exec_bit).unwrap_or(1)]);
                // STREAMED, not `std::fs::read`: reading each file into a fresh
                // `Vec` costs an allocation plus a full copy out of the page cache
                // before a byte is hashed. MEASURED over a 0.609 GiB tree (warm):
                // `std::fs::read` gave 0.583 s at 1034 MiB/s, `update_reader`
                // 0.266 s at 2186 MiB/s.
                //
                // The length is folded AFTER the content and is the count this
                // loop actually read, not the one `stat` reported. Framing is
                // just as unambiguous either way, and taking it from the read
                // means the digest can never describe a length the hash did not
                // cover — a file that changed size between the walk and the read
                // rotates the address instead of silently disagreeing with it.
                let file = std::fs::File::open(&abs).map_err(|e| {
                    KataError::Config(format!(
                        "provider store: cannot read `{}`: {e}",
                        abs.display()
                    ))
                })?;
                let before = hasher.count();
                hasher.update_reader(&file).map_err(|e| {
                    KataError::Config(format!(
                        "provider store: cannot read `{}`: {e}",
                        abs.display()
                    ))
                })?;
                let len = hasher.count() - before;
                hasher.update(&len.to_le_bytes());
                files += 1;
                bytes += len;
            }
        }
    }

    Ok(TreeDigest {
        hex: hasher.finalize().to_hex().to_string(),
        files,
        bytes,
    })
}

/// Walk `dir` (at relative path `rel`) into `out`, refusing node types the
/// store does not represent.
fn collect_tree(
    root: &Path,
    rel: &Path,
    out: &mut BTreeMap<PathBuf, (NodeKind, u64)>,
) -> KataResult<()> {
    let abs = root.join(rel);
    let entries = std::fs::read_dir(&abs).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot read directory `{}`: {e}",
            abs.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot read an entry of `{}`: {e}",
                abs.display()
            ))
        })?;
        let child_rel = rel.join(entry.file_name());
        let file_type = entry.file_type().map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot stat `{}`: {e}",
                root.join(&child_rel).display()
            ))
        })?;
        if file_type.is_symlink() {
            out.insert(child_rel, (NodeKind::Symlink, 0));
        } else if file_type.is_dir() {
            out.insert(child_rel.clone(), (NodeKind::Dir, 0));
            collect_tree(root, &child_rel, out)?;
        } else if file_type.is_file() {
            let exec = executable_bit(&root.join(&child_rel))?;
            out.insert(child_rel, (NodeKind::File, u64::from(exec)));
        } else {
            return Err(KataError::Config(format!(
                "provider store: `{}` is neither a file, directory, nor symlink. The store \
                 carries no devices, sockets or fifos — refusing rather than skipping it, \
                 because a node inside the entry that the address does not cover would make \
                 the address describe less than what runs.",
                root.join(&child_rel).display()
            )));
        }
    }
    Ok(())
}

/// `true` when any of the three execute bits is set.
fn executable_bit(path: &Path) -> KataResult<bool> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot stat `{}`: {e}",
            path.display()
        ))
    })?;
    Ok(meta.permissions().mode() & 0o111 != 0)
}

// ---------------------------------------------------------------------------
// Copy + seal
// ---------------------------------------------------------------------------

/// Recursively copy `src` to `dst`, preserving symlinks as symlinks and the
/// executable bit on files.
///
/// Deliberately NOT `cp -a` via a subprocess: this store's guarantee is that the
/// hash covers the copy, and a copy performed by a tool whose exact preservation
/// semantics vary by implementation (GNU vs BSD `cp`, `--reflink` support, ACLs,
/// xattrs) would make the store's behaviour depend on the host's coreutils.
fn copy_tree(src: &Path, dst: &Path) -> KataResult<()> {
    std::fs::create_dir_all(dst).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot create `{}`: {e}",
            dst.display()
        ))
    })?;
    let entries = std::fs::read_dir(src).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot read `{}`: {e}",
            src.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot read an entry of `{}`: {e}",
                src.display()
            ))
        })?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let file_type = entry.file_type().map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot stat `{}`: {e}",
                from.display()
            ))
        })?;
        if file_type.is_symlink() {
            let target = std::fs::read_link(&from).map_err(|e| {
                KataError::Config(format!(
                    "provider store: cannot read symlink `{}`: {e}",
                    from.display()
                ))
            })?;
            std::os::unix::fs::symlink(&target, &to).map_err(|e| {
                KataError::Config(format!(
                    "provider store: cannot create symlink `{}`: {e}",
                    to.display()
                ))
            })?;
        } else if file_type.is_dir() {
            copy_tree(&from, &to)?;
        } else if file_type.is_file() {
            copy_file(&from, &to)?;
        } else {
            return Err(KataError::Config(format!(
                "provider store: `{}` is neither a file, directory, nor symlink — refusing to \
                 provision a tree carrying a device, socket or fifo.",
                from.display()
            )));
        }
    }
    Ok(())
}

/// Copy one regular file's bytes to `dst`, carrying only its executable bit —
/// the one mode bit [`hash_tree`] folds; [`seal_tree`] rewrites the rest.
fn copy_file(src: &Path, dst: &Path) -> KataResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::copy(src, dst).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot copy `{}` to `{}`: {e}",
            src.display(),
            dst.display()
        ))
    })?;
    let mode = if executable_bit(src)? { 0o755 } else { 0o644 };
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot set mode on `{}`: {e}",
            dst.display()
        ))
    })
}

/// Copy one declared member to `dst` through ONE descriptor opened with
/// `O_NOFOLLOW` and re-checked as a regular file, so a path swapped for a link
/// after [`check_declared_member`] ran is refused rather than followed.
fn copy_declared_member(member: &str, path: &Path, dst: &Path) -> KataResult<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let unreadable = |e: std::io::Error| {
        KataError::Config(format!(
            "provider store: the declared member `{member}` at `{}` cannot be read as a regular \
             file: {e}",
            path.display()
        ))
    };
    let mut source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(unreadable)?;
    let metadata = source.metadata().map_err(unreadable)?;
    if !metadata.file_type().is_file() {
        return Err(KataError::Config(format!(
            "provider store: the declared member `{member}` at `{}` is not a regular file.",
            path.display()
        )));
    }
    let mut target = std::fs::File::create_new(dst).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot create `{}`: {e}",
            dst.display()
        ))
    })?;
    std::io::copy(&mut source, &mut target).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot copy `{}` to `{}`: {e}",
            path.display(),
            dst.display()
        ))
    })?;
    let mode = if metadata.permissions().mode() & 0o111 != 0 {
        0o755
    } else {
        0o644
    };
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        KataError::Config(format!(
            "provider store: cannot set mode on `{}`: {e}",
            dst.display()
        ))
    })
}

/// One [`ProviderStore::provision_with_members`] member, checked before
/// anything is staged.
fn check_declared_member(source: &Path, member: &str, path: &Path) -> KataResult<()> {
    let mut components = Path::new(member).components();
    let plain = matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(only)), None) if only == member
    );
    if !plain {
        return Err(KataError::Config(format!(
            "provider store: the declared member name {member:?} is not one plain file name; a \
             member lands at the top of the entry, beside `{PROVIDER_BINARY_PREFIX}<name>`."
        )));
    }
    if std::fs::symlink_metadata(source.join(member)).is_ok() {
        return Err(KataError::Config(format!(
            "provider store: `{source}` already holds `{member}`, and `{member}` is also declared \
             as `{path}`. One file may have one answer: remove it from the source directory or \
             drop the declaration.",
            source = source.display(),
            path = path.display(),
        )));
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(meta) => Err(KataError::Config(format!(
            "provider store: the declared member `{member}` at `{path}` is not a regular file \
             (it is a {kind}). A member is copied verbatim and a link is never followed — \
             resolve it to the file it names and declare that.",
            path = path.display(),
            kind = if meta.file_type().is_symlink() {
                "symlink"
            } else if meta.file_type().is_dir() {
                "directory"
            } else {
                "special file"
            },
        ))),
        Err(e) => Err(KataError::Config(format!(
            "provider store: the declared member `{member}` at `{path}` cannot be read: {e}",
            path = path.display(),
        ))),
    }
}

/// Seal a published entry: files read-only, directories read + traverse only.
///
/// # `0555`, not `0444`, for an EXECUTABLE — and that is not a detail
///
/// `0444` strips the execute bit, and an entry exists to be EXECUTED: the store
/// would publish a `kata-provider-<name>` kata could read and not spawn (`EACCES`),
/// with its address still minted.
///
/// Sealing is DEFENCE IN DEPTH, never the guarantee. It stops a careless
/// overwrite and makes tampering deliberate; it cannot stop the uid that owns
/// the store, which is why [`verify_store_entry`] re-reads the bytes anyway.
///
/// Directories are sealed LAST (deepest first) so the walk can still enter them.
fn seal_tree(root: &Path) -> KataResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut dirs = vec![root.to_path_buf()];
    let mut seen_dirs = Vec::new();
    while let Some(dir) = dirs.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot read `{}` while sealing: {e}",
                dir.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                KataError::Config(format!(
                    "provider store: cannot read an entry of `{}` while sealing: {e}",
                    dir.display()
                ))
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| {
                KataError::Config(format!(
                    "provider store: cannot stat `{}` while sealing: {e}",
                    path.display()
                ))
            })?;
            if file_type.is_symlink() {
                // A symlink's own mode is not consulted by the kernel; sealing
                // it would be a no-op wearing a guarantee's name.
                continue;
            }
            if file_type.is_dir() {
                dirs.push(path);
                continue;
            }
            let exec = executable_bit(&path)?;
            let mode = if exec { 0o555 } else { 0o444 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).map_err(
                |e| {
                    KataError::Config(format!(
                        "provider store: cannot seal `{}`: {e}",
                        path.display()
                    ))
                },
            )?;
        }
        seen_dirs.push(dir);
    }
    for dir in seen_dirs.into_iter().rev() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).map_err(|e| {
            KataError::Config(format!(
                "provider store: cannot seal directory `{}`: {e}",
                dir.display()
            ))
        })?;
    }
    Ok(())
}

/// Restore owner-write on a sealed tree so it can be removed or replaced.
///
/// A production need, not a test hook: [`ProviderStore::provision`] must be able
/// to delete its own staging copy after sealing it, and an operator retiring a
/// generation needs the same. Without it a store entry is undeletable without
/// `chmod -R u+w` by hand — which the refusal messages therefore also name, for
/// an operator who is not going through this API.
///
/// # Errors
///
/// Any filesystem operation failing.
pub fn unseal_tree(root: &Path) -> KataResult<()> {
    use std::os::unix::fs::PermissionsExt;

    if !root.exists() {
        return Ok(());
    }
    // Directories first and shallowest-first: a 0500 directory cannot be walked
    // into to reach its children until it is writable again.
    let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700));
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
                dirs.push(path);
            } else {
                let exec = executable_bit(&path).unwrap_or(false);
                let mode = if exec { 0o755 } else { 0o644 };
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

/// An RAII guard that [`unseal_tree`]s `root` when it is dropped.
///
/// **THE LEAK IT CLOSES: a store provisioned into a [`tempfile::TempDir`] is
/// never removed** — measured at 1,201 directories under `/tmp`, 4.1 GB, every
/// one of them `<tmpdir>/store/<digest>/…`. `TempDir`'s `Drop` calls
/// `remove_dir_all` and DISCARDS the result — it has no other option, a
/// destructor cannot fail — and `remove_dir_all` cannot unlink the children of a
/// `0500` directory, which is exactly what [`seal_tree`] writes. So the removal
/// returns `EACCES`, nothing reports it, and the directory stays on disk
/// forever. The seal is not the bug: it is the guarantee. What this guard adds
/// is a caller that lifts it before the removal runs.
///
/// **Every caller that provisions a store into a temp root must hold one, the
/// live smokes included** — they are the biggest single producer: one
/// `just smoke-no-budget` without guards left six `.tmp*` rigs totalling
/// **615 MiB**. Nothing goes red when a caller forgets the guard, so the only
/// way to find a missing one is to measure the temp root.
///
/// # Drop order is the whole mechanism
///
/// Locals drop in REVERSE declaration order, so the guard must be declared
/// AFTER the `TempDir` it protects:
///
/// ```ignore
/// let tmp = tempfile::tempdir()?;
/// let _unseal = UnsealOnDrop::new(tmp.path());   // drops FIRST, unsealing
/// let store = ProviderStore::new(&tmp.path().join("store"));
/// // ... `tmp` drops SECOND, and now `remove_dir_all` succeeds
/// ```
///
/// Declared before the `TempDir`, it unseals a tree that is already gone — which
/// is harmless and also useless, so the ordering is stated rather than implied.
///
/// # Why a guard rather than a call at the end of the test
///
/// A test that fails asserts BEFORE its last line. A trailing `unseal_tree` runs
/// on the green path only, which leaks precisely on the runs an author is most
/// likely to repeat. Unwinding runs destructors, so this one fires on both.
pub struct UnsealOnDrop {
    root: std::path::PathBuf,
}

impl UnsealOnDrop {
    /// Guard `root`, unsealing it when this value drops.
    #[must_use]
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl Drop for UnsealOnDrop {
    fn drop(&mut self) {
        // Best-effort by construction: a destructor has nowhere to report to,
        // and the failure this exists to prevent is itself a silently-discarded
        // removal error. An absent root is already `Ok(())`.
        let _ = unseal_tree(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::copy_declared_member;

    /// **The toolhost directory answers only as exactly one regular file its
    /// owner may execute.** A well-formed `toolhost/kata-toolhost` resolves, and
    /// every arm of the stated refused set refuses `toolhost_unavailable`, naming
    /// what it found: a symlinked `toolhost`, a `toolhost` that is a file, a
    /// missing `toolhost`, one that cannot be listed, an extra file beside the
    /// program, an empty directory, a program whose metadata cannot be read, a
    /// symlinked program, a program that is a directory, and a program without
    /// its owner execute bit (no bit at all, and group and other bits alone).
    ///
    /// **Would red if:** `toolhost_dir` followed a symlink (`is_dir`/`is_file`
    /// instead of `symlink_metadata`), accepted a directory holding a second
    /// file the guest would see, or answered a program the init could not exec.
    #[test]
    fn the_toolhost_dir_refuses_a_symlink_an_extra_file_and_a_missing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        use super::{ResolvedProvider, TOOLHOST_DIRECTORY, TOOLHOST_PROGRAM};
        use crate::execution_route::ExternalProviderAddress;

        let resolved = |entry: &std::path::Path| ResolvedProvider {
            name: "youki".to_owned(),
            address: ExternalProviderAddress::from_verified_hex(&"0".repeat(64)),
            entry: entry.to_path_buf(),
            binary: entry.join("kata-provider-youki"),
        };
        let set_mode = |path: &std::path::Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
        };
        let root = tempfile::tempdir().expect("tempdir");
        let program = |dir: &std::path::Path, mode: u32| {
            std::fs::create_dir_all(dir).expect("toolhost dir");
            let path = dir.join(TOOLHOST_PROGRAM);
            std::fs::write(&path, b"\x7fELF").expect("program");
            set_mode(&path, mode);
        };
        let entry = |name: &str| {
            let entry = root.path().join(name);
            std::fs::create_dir_all(&entry).expect("an entry");
            entry
        };
        let elsewhere = entry("elsewhere");
        program(&elsewhere, 0o755);

        let well_formed = entry("well-formed");
        program(&well_formed.join(TOOLHOST_DIRECTORY), 0o755);
        assert_eq!(
            resolved(&well_formed)
                .toolhost_dir()
                .expect("a well-formed toolhost dir"),
            well_formed.join(TOOLHOST_DIRECTORY)
        );
        let owner_only = entry("owner-only");
        program(&owner_only.join(TOOLHOST_DIRECTORY), 0o500);
        assert!(resolved(&owner_only).toolhost_dir().is_ok());

        let linked_dir = entry("linked-dir");
        std::os::unix::fs::symlink(&elsewhere, linked_dir.join(TOOLHOST_DIRECTORY)).unwrap();
        let file_not_dir = entry("file-not-dir");
        std::fs::write(file_not_dir.join(TOOLHOST_DIRECTORY), b"x").unwrap();
        let missing_dir = entry("missing-dir");
        let unlistable = entry("unlistable");
        program(&unlistable.join(TOOLHOST_DIRECTORY), 0o755);
        let extra = entry("extra-file");
        program(&extra.join(TOOLHOST_DIRECTORY), 0o755);
        std::fs::write(extra.join(TOOLHOST_DIRECTORY).join("ip"), b"ip").unwrap();
        let empty = entry("empty");
        std::fs::create_dir_all(empty.join(TOOLHOST_DIRECTORY)).unwrap();
        let unsearchable = entry("unsearchable");
        program(&unsearchable.join(TOOLHOST_DIRECTORY), 0o755);
        let linked_program = entry("linked-program");
        std::fs::create_dir_all(linked_program.join(TOOLHOST_DIRECTORY)).unwrap();
        std::os::unix::fs::symlink(
            elsewhere.join(TOOLHOST_PROGRAM),
            linked_program
                .join(TOOLHOST_DIRECTORY)
                .join(TOOLHOST_PROGRAM),
        )
        .unwrap();
        let program_dir = entry("program-dir");
        std::fs::create_dir_all(program_dir.join(TOOLHOST_DIRECTORY).join(TOOLHOST_PROGRAM))
            .unwrap();
        let not_executable = entry("not-executable");
        program(&not_executable.join(TOOLHOST_DIRECTORY), 0o644);
        let others_only = entry("others-only");
        program(&others_only.join(TOOLHOST_DIRECTORY), 0o611);

        // Listing needs read on the directory; reading a child's metadata needs
        // search. Restored below, before the tempdir is removed.
        set_mode(&unlistable.join(TOOLHOST_DIRECTORY), 0o300);
        set_mode(&unsearchable.join(TOOLHOST_DIRECTORY), 0o400);

        let cases = [
            (
                "a symlinked toolhost directory",
                &linked_dir,
                "is not a directory",
            ),
            (
                "a toolhost that is a file",
                &file_not_dir,
                "is not a directory",
            ),
            ("a missing directory", &missing_dir, "is absent"),
            ("an unlistable directory", &unlistable, "cannot be listed"),
            ("an extra file", &extra, "[\"ip\", \"kata-toolhost\"]"),
            ("an empty directory", &empty, "holds []"),
            ("an unsearchable directory", &unsearchable, "cannot be read"),
            (
                "a symlinked program",
                &linked_program,
                "is not a regular file",
            ),
            (
                "a program that is a directory",
                &program_dir,
                "is not a regular file",
            ),
            ("a program with no execute bit", &not_executable, "mode 644"),
            ("a program others may execute", &others_only, "mode 611"),
        ];
        let refusals: Vec<(&str, String)> = cases
            .iter()
            .map(|(case, entry, _)| {
                let refusal = resolved(entry).toolhost_dir().map_or_else(
                    |refusal| refusal.to_string(),
                    |dir| format!("ADMITTED {}", dir.display()),
                );
                (*case, refusal)
            })
            .collect();
        set_mode(&unlistable.join(TOOLHOST_DIRECTORY), 0o755);
        set_mode(&unsearchable.join(TOOLHOST_DIRECTORY), 0o755);
        for ((case, refusal), (_, _, names)) in refusals.iter().zip(&cases) {
            assert!(
                refusal.contains("toolhost_unavailable") && refusal.contains(names),
                "{case}: {refusal}"
            );
        }
    }

    /// The copy re-checks on the descriptor it reads: a member path that is a
    /// link by the time it is copied — after `check_declared_member` passed —
    /// is refused, not followed, and leaves no file in the staging tree.
    #[test]
    fn a_member_that_is_a_link_at_copy_time_is_refused_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real-ip");
        std::fs::write(&real, b"ip").expect("real member");
        let link = dir.path().join("ip-link");
        std::os::unix::fs::symlink(&real, &link).expect("link");
        let dst = dir.path().join("staged-ip");

        let refusal =
            copy_declared_member("ip", &link, &dst).expect_err("a link is refused at copy time");
        assert!(
            refusal
                .to_string()
                .contains("cannot be read as a regular file"),
            "{refusal}"
        );
        assert!(!dst.exists(), "nothing was staged");

        copy_declared_member("ip", &real, &dst).expect("a regular file copies");
        assert_eq!(std::fs::read(&dst).expect("staged bytes"), b"ip");
    }

    /// The staged member's mode is decided by the source's execute bits alone:
    /// any execute bit stages `0o755`, none stages `0o644`.
    #[test]
    fn a_member_is_staged_executable_exactly_when_its_source_has_an_execute_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        for (source_mode, staged_mode) in [
            (0o644, 0o644),
            (0o600, 0o644),
            (0o700, 0o755),
            (0o751, 0o755),
        ] {
            let src = dir.path().join(format!("member-{source_mode:o}"));
            std::fs::write(&src, b"member").expect("source member");
            std::fs::set_permissions(&src, std::fs::Permissions::from_mode(source_mode))
                .expect("source mode");
            let dst = dir.path().join(format!("staged-{source_mode:o}"));

            copy_declared_member("member", &src, &dst).expect("a regular file copies");
            let mode = std::fs::metadata(&dst)
                .expect("staged metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, staged_mode, "source mode {source_mode:o}");
        }
    }
}
