//! The effective owner's home: the one per-owner root every kata process of a
//! uid agrees on.
//!
//! Resolved from the effective account record, never from ambient `HOME`. The
//! native user manager runs the installed service under that account identity,
//! a `kata-worker` daemon of the same uid reads the same record, and an
//! interactive shell may export any `HOME` it likes; resolving from `HOME`
//! would let one of them publish or read per-owner state another never sees.
//!
//! This crate never resolves a home on its own behalf: each binary calls
//! [`effective_owner_home`] and hands the result (or a path under it) to the
//! worker's sources, so a cell can point them at a fixture instead.

use std::path::PathBuf;

/// Why the effective owner's home could not be resolved. Each arm refuses:
/// there is no fallback home.
#[derive(Debug)]
pub enum OwnerHomeError {
    /// The account database could not be read for the effective uid.
    AccountLookup {
        /// The effective uid.
        uid: u32,
        /// The lookup's own error.
        source: nix::Error,
    },
    /// The effective uid has no account record.
    NoAccount {
        /// The effective uid.
        uid: u32,
    },
    /// The account record names an empty or relative home.
    NotAbsolute {
        /// The home the record names.
        home: PathBuf,
    },
    /// The home could not be inspected.
    Inspect {
        /// The home the record names.
        home: PathBuf,
        /// The inspection's own error.
        source: std::io::Error,
    },
    /// The home is a symlink or not a directory.
    NotADirectory {
        /// The home the record names.
        home: PathBuf,
    },
    /// The home is owned by another uid.
    ForeignOwner {
        /// The home the record names.
        home: PathBuf,
        /// The effective uid.
        uid: u32,
        /// The uid that owns the home.
        owner: u32,
    },
}

impl std::fmt::Display for OwnerHomeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountLookup { uid, .. } => write!(
                formatter,
                "resolving the effective Kata owner account (uid {uid})"
            ),
            Self::NoAccount { uid } => {
                write!(
                    formatter,
                    "effective Kata owner uid {uid} has no account record"
                )
            }
            Self::NotAbsolute { home } => write!(
                formatter,
                "effective Kata owner account home must be a nonempty absolute path; got {}",
                home.display()
            ),
            Self::Inspect { home, .. } => write!(
                formatter,
                "inspecting effective Kata owner account home {}",
                home.display()
            ),
            Self::NotADirectory { home } => write!(
                formatter,
                "effective Kata owner account home {} must be an existing real directory",
                home.display()
            ),
            Self::ForeignOwner { home, uid, owner } => write!(
                formatter,
                "effective Kata owner account home {} must be owned by uid {uid}; found uid \
                 {owner}",
                home.display()
            ),
        }
    }
}

impl std::error::Error for OwnerHomeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AccountLookup { source, .. } => Some(source),
            Self::Inspect { source, .. } => Some(source),
            Self::NoAccount { .. }
            | Self::NotAbsolute { .. }
            | Self::NotADirectory { .. }
            | Self::ForeignOwner { .. } => None,
        }
    }
}

/// The effective account's home: an absolute, real (not symlinked) directory
/// owned by the effective uid.
///
/// # Errors
/// [`OwnerHomeError`] naming which of those facts failed.
pub fn effective_owner_home() -> Result<PathBuf, OwnerHomeError> {
    use std::os::unix::fs::MetadataExt as _;

    let uid = nix::unistd::Uid::effective();
    let user = nix::unistd::User::from_uid(uid)
        .map_err(|source| OwnerHomeError::AccountLookup {
            uid: uid.as_raw(),
            source,
        })?
        .ok_or(OwnerHomeError::NoAccount { uid: uid.as_raw() })?;
    let home = validate_account_home(user.dir.into_os_string())?;
    let metadata = std::fs::symlink_metadata(&home).map_err(|source| OwnerHomeError::Inspect {
        home: home.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OwnerHomeError::NotADirectory { home });
    }
    if metadata.uid() != uid.as_raw() {
        return Err(OwnerHomeError::ForeignOwner {
            home,
            uid: uid.as_raw(),
            owner: metadata.uid(),
        });
    }
    Ok(home)
}

/// kata's own logins directory under the effective owner's home
/// (`kata_agent_nanocode::credential::logins_dir`).
///
/// # Errors
/// [`effective_owner_home`]'s.
pub fn kata_logins_dir() -> Result<PathBuf, OwnerHomeError> {
    #[cfg(feature = "test-support")]
    if let Some(dir) = test_logins_dir() {
        return Ok(dir);
    }
    Ok(kata_agent_nanocode::credential::logins_dir(
        &effective_owner_home()?,
    ))
}

/// TEST SUPPORT — a `test-support` build (never a shipped one: only
/// dev-dependencies enable the feature) takes kata's logins directory from
/// `KATA_TEST_KATA_LOGINS_DIR` when this process's environment sets it, and
/// logs that it did, so a cell that runs the real `kata` binary (`kata init`
/// then `kata doctor`) reads a directory it planted, never the effective
/// owner's own logins. Unset, the directory is the owner's.
#[cfg(feature = "test-support")]
fn test_logins_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("KATA_TEST_KATA_LOGINS_DIR")?);
    tracing::warn!(
        "test-support: kata's logins directory is {} (`KATA_TEST_KATA_LOGINS_DIR`)",
        dir.display()
    );
    Some(dir)
}

/// kata's own logins directory as a binary resolved it, a failed resolution
/// included: what every binary hands its worker's credential source
/// ([`KataLoginsDir::resolve`]).
///
/// A failed resolution does not stop a worker from starting. Only a
/// `credential.source = "kata_login"` turn reads this directory; such a turn
/// refuses `credential_unavailable` naming the [`OwnerHomeError`], and every
/// `env:` and shell stage runs as it would with the directory resolved.
#[derive(Clone, Debug)]
pub enum KataLoginsDir {
    /// The logins directory under the effective owner's home.
    Resolved(PathBuf),
    /// The effective owner's home could not be resolved.
    Unresolved(std::sync::Arc<OwnerHomeError>),
}

impl KataLoginsDir {
    /// Resolve [`kata_logins_dir`], keeping its error rather than refusing.
    #[must_use]
    pub fn resolve() -> Self {
        match kata_logins_dir() {
            Ok(dir) => Self::Resolved(dir),
            Err(error) => Self::Unresolved(std::sync::Arc::new(error)),
        }
    }
}

fn validate_account_home(value: std::ffi::OsString) -> Result<PathBuf, OwnerHomeError> {
    let home = PathBuf::from(value);
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return Err(OwnerHomeError::NotAbsolute { home });
    }
    Ok(home)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_account_home_rejects_empty_and_relative_values() {
        for value in [
            std::ffi::OsString::new(),
            std::ffi::OsString::from("relative/home"),
        ] {
            let error =
                validate_account_home(value).expect_err("unstable owner HOME must fail closed");
            assert!(error.to_string().contains("account home"), "{error}");
        }
        assert_eq!(
            validate_account_home(std::ffi::OsString::from("/owner/home")).unwrap(),
            PathBuf::from("/owner/home")
        );
    }

    #[test]
    fn effective_owner_home_is_an_existing_owned_directory() {
        use std::os::unix::fs::MetadataExt as _;

        let home = effective_owner_home().unwrap();
        let metadata = std::fs::symlink_metadata(&home).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    }
}
