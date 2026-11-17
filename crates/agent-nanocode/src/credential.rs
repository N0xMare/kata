//! kata's OWN login for the embedded harness: the one HOST-side module of this
//! crate.
//!
//! The adapter files run no host I/O (`crates/agent/tests/adapter_contract.rs`
//! scans them); this file is excluded from that scan by name, because it is
//! where kata's login files are written, checked, loaded and refreshed. Its
//! callers are the worker's credential lift (pre-container, through [`load`])
//! and the `kata login` / `kata logout` / `kata doctor` surfaces.
//!
//! # The files
//!
//! Every file lives in ONE directory, [`logins_dir`] under the effective
//! owner's home (the binary resolves the home from the account record, never
//! from `HOME`, and names the directory to the worker). The directory is
//! owner-only (no group or world bits) and owned by the effective uid; each
//! file is a regular file with one link, owned by the effective uid, with no
//! group or world bits ([`check_logins_dir`], [`check_login_file`]). A file
//! that fails either check is refused, never repaired.
//!
//! | [`LoginFile`] | written by | content |
//! |---|---|---|
//! | `openai-chatgpt.json` (+ `.lock`) | `kata login openai` (the browser or the device-code flow: one file kind) | kata's store of nanocode's ChatGPT subscription state: `{"revision": n, "state": "<nanocode's payload>"}` |
//! | `openai-api-key` | `kata login openai --api-key` | one line |
//! | `anthropic-api-key` | `kata login anthropic --api-key` | one line |
//!
//! kata never reads another tool's login in place of these: not
//! `~/.codex/auth.json`, not `$NANOCODE_HOME/auth.json`, not
//! `~/.claude/.credentials.json`. Nothing here calls nanocode's readers of
//! those files (`OpenAiAuth::chatgpt`, `load_chatgpt_auth` on a path kata did
//! not write).
//!
//! # Who refreshes, and why exactly once
//!
//! The ChatGPT login rotates its refresh token on every refresh, so two
//! refreshes presenting the same token would burn the login (the issuer treats
//! the second as reuse). kata refreshes through nanocode's
//! `ChatGptSubscription` over [`FileStore`], kata's implementation of its host
//! contract, and every refresh serializes on an exclusive `flock` of
//! `openai-chatgpt.json.lock`, held from before the token request until the
//! rotated state is committed:
//!
//! * a refresh that finds, under the lock, a stored refresh token other than
//!   the one it was about to present does not contact the issuer: it answers
//!   nanocode `409 kata_refresh_superseded`, and nanocode re-reads the store and
//!   adopts the rotation another holder committed;
//! * otherwise it presents the token, and keeps the lock until nanocode's next
//!   `compare_and_swap` commits the answer (or the issuer refused, after which
//!   nanocode commits nothing).
//!
//! `flock` locks belong to an open file description, so two loads in ONE
//! process contend exactly as two processes do: each turn loads its own source
//! and the lock, not a process-local cache, is what serializes them
//! (`two_refreshes_of_one_file_rotate_once`, in the worker's credential lift).
//!
//! Stated residuals: a process that dies between the issuer's answer and the
//! commit loses the rotated token, and the next refresh is refused as reuse
//! (`kata login openai` again); a 2xx answer nanocode cannot decode leaves the
//! lock held until that source is dropped (the end of its turn), and another
//! holder waits at most [`LOCK_WAIT`] before refusing.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use kata_types::agent::AdapterKind;
use kata_types::metering::CredentialMode;
use nanocode_backend_codex::client::auth::{
    ChatGptCredentialSeed, ChatGptLogin, ChatGptLoginStatus, ChatGptSubscription,
    ChatGptSubscriptionError, ChatGptSubscriptionHost, SubscriptionCommit, SubscriptionFuture,
    SubscriptionHostError, SubscriptionHttpRequest, SubscriptionHttpResponse,
    SubscriptionStoreValue,
};
use serde::{Deserialize, Serialize};

use crate::HarnessAuth;

/// The logins directory, relative to the effective owner's home.
pub const LOGINS_DIR: &str = ".config/kata/logins";

/// The nanocode subscription key kata stores its ChatGPT state under. The key
/// is nanocode's name for one store; [`FileStore`] serves exactly this one.
const CHATGPT_KEY: &str = "openai-chatgpt";

/// How long a refresh or a commit waits for another holder's lock before it
/// refuses. One issuer round trip is bounded by [`ISSUER_TIMEOUT`], so a holder
/// that keeps the lock longer is stuck, not slow.
pub const LOCK_WAIT: Duration = Duration::from_secs(60);

/// One HTTP round trip to the issuer.
const ISSUER_TIMEOUT: Duration = Duration::from_secs(30);

/// The answer a superseded refresh gets instead of an issuer round trip.
const SUPERSEDED_STATUS: u16 = 409;
const SUPERSEDED_BODY: &str = r#"{"error":"kata_refresh_superseded"}"#;

/// The logins directory under `owner_home`.
#[must_use]
pub fn logins_dir(owner_home: &Path) -> PathBuf {
    owner_home.join(LOGINS_DIR)
}

/// A provider kata holds a login for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginProvider {
    /// OpenAI: a ChatGPT login or an API key.
    Openai,
    /// Anthropic: an API key. kata's Claude login is not in this build.
    Anthropic,
}

impl LoginProvider {
    /// The provider's spelling on the `kata login` / `kata logout` command line.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    /// The provider a harness kind's model calls go to.
    #[must_use]
    pub const fn of_kind(kind: AdapterKind) -> Self {
        match kind {
            AdapterKind::NanocodeOpenai => Self::Openai,
            AdapterKind::NanocodeAnthropic => Self::Anthropic,
        }
    }

    /// The file a credential of `mode` for this provider is stored in;
    /// `None` for an Anthropic subscription, which kata cannot log in yet.
    #[must_use]
    pub const fn file(self, mode: CredentialMode) -> Option<LoginFile> {
        match (self, mode) {
            (Self::Openai, CredentialMode::Subscription) => Some(LoginFile::OpenAiChatGpt),
            (Self::Openai, CredentialMode::ApiKey) => Some(LoginFile::OpenAiApiKey),
            (Self::Anthropic, CredentialMode::ApiKey) => Some(LoginFile::AnthropicApiKey),
            (Self::Anthropic, CredentialMode::Subscription) => None,
        }
    }

    /// Every file this provider can have.
    #[must_use]
    pub fn files(self) -> Vec<LoginFile> {
        LoginFile::ALL
            .into_iter()
            .filter(|file| file.provider() == self)
            .collect()
    }
}

/// One of kata's login files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginFile {
    /// The ChatGPT login's store.
    OpenAiChatGpt,
    /// An OpenAI API key.
    OpenAiApiKey,
    /// An Anthropic API key.
    AnthropicApiKey,
}

impl LoginFile {
    /// Every login file kata knows.
    pub const ALL: [Self; 3] = [
        Self::OpenAiChatGpt,
        Self::OpenAiApiKey,
        Self::AnthropicApiKey,
    ];

    /// The file's name inside the logins directory.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::OpenAiChatGpt => "openai-chatgpt.json",
            Self::OpenAiApiKey => "openai-api-key",
            Self::AnthropicApiKey => "anthropic-api-key",
        }
    }

    /// The command that writes this file.
    #[must_use]
    pub const fn login_command(self) -> &'static str {
        match self {
            Self::OpenAiChatGpt => "kata login openai",
            Self::OpenAiApiKey => "kata login openai --api-key",
            Self::AnthropicApiKey => "kata login anthropic --api-key",
        }
    }

    /// The credential mode this file holds.
    #[must_use]
    pub const fn mode(self) -> CredentialMode {
        match self {
            Self::OpenAiChatGpt => CredentialMode::Subscription,
            Self::OpenAiApiKey | Self::AnthropicApiKey => CredentialMode::ApiKey,
        }
    }

    /// The provider this file is a login for.
    #[must_use]
    pub const fn provider(self) -> LoginProvider {
        match self {
            Self::OpenAiChatGpt | Self::OpenAiApiKey => LoginProvider::Openai,
            Self::AnthropicApiKey => LoginProvider::Anthropic,
        }
    }

    /// The file's path in `logins_dir`.
    #[must_use]
    pub fn path(self, logins_dir: &Path) -> PathBuf {
        logins_dir.join(self.file_name())
    }
}

/// Why kata's own login could not be used. Every arm refuses: there is no
/// fallback credential, and no other tool's login is read in its place.
#[derive(Debug)]
pub enum KataLoginError {
    /// The kind's provider has no kata login of this mode in this build.
    ModeUnavailable {
        /// The provider.
        provider: LoginProvider,
        /// The declared mode.
        mode: CredentialMode,
    },
    /// The logins directory or the login file does not exist.
    Absent {
        /// The file that was looked for.
        file: LoginFile,
        /// The missing path.
        path: PathBuf,
    },
    /// The directory or the file fails the owner-only check.
    Insecure {
        /// The path that failed.
        path: PathBuf,
        /// What failed.
        reason: String,
    },
    /// The file could not be read or written.
    Io {
        /// The path.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The file's content is not what kata wrote.
    Malformed {
        /// The path.
        path: PathBuf,
        /// What is wrong with it.
        detail: String,
    },
    /// An API key `kata login --api-key` will not store.
    KeyRefused {
        /// The file it was for.
        file: LoginFile,
        /// Why it is refused.
        detail: String,
    },
    /// The ChatGPT store holds no completed login.
    NotSignedIn {
        /// The store's path.
        path: PathBuf,
    },
    /// The access token is expired and kata's refresh did not renew it.
    Expired {
        /// The store's path.
        path: PathBuf,
    },
    /// nanocode refused the stored login or its refresh.
    Harness {
        /// The store's path.
        path: PathBuf,
        /// nanocode's error.
        source: ChatGptSubscriptionError,
    },
    /// The browser login did not complete.
    Login(nanocode_backend_codex::client::auth::ChatGptAuthError),
    /// The device-code login did not complete; nothing was stored.
    DeviceLogin(DeviceLoginFailure),
}

impl KataLoginError {
    /// The refusal name the worker's credential lift answers this error under.
    #[must_use]
    pub const fn refusal(&self) -> &'static str {
        match self {
            Self::Expired { .. } => "credential_expired",
            Self::ModeUnavailable { .. }
            | Self::Absent { .. }
            | Self::Insecure { .. }
            | Self::Io { .. }
            | Self::Malformed { .. }
            | Self::KeyRefused { .. }
            | Self::NotSignedIn { .. }
            | Self::Harness { .. }
            | Self::Login(_)
            | Self::DeviceLogin(_) => "credential_unavailable",
        }
    }
}

impl std::fmt::Display for KataLoginError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModeUnavailable { provider, mode } => write!(
                formatter,
                "kata holds no `{}` login for {}; this build logs {} in with `kata login {} \
                 --api-key` only",
                mode.as_label(),
                provider.as_label(),
                provider.as_label(),
                provider.as_label()
            ),
            Self::Absent { file, path } => write!(
                formatter,
                "kata's login file {} does not exist; run `{}`",
                path.display(),
                file.login_command()
            ),
            Self::Insecure { path, reason } => write!(
                formatter,
                "kata's login path {} is refused: {reason}",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(formatter, "kata's login file {}: {source}", path.display())
            }
            Self::Malformed { path, detail } => write!(
                formatter,
                "kata's login file {} is not a login kata wrote ({detail}); run the login again",
                path.display()
            ),
            Self::KeyRefused { file, detail } => write!(
                formatter,
                "`{}` stores no such key ({detail}); nothing was written",
                file.login_command()
            ),
            Self::NotSignedIn { path } => write!(
                formatter,
                "kata's ChatGPT login at {} holds no completed login; run `kata login openai`",
                path.display()
            ),
            Self::Expired { path } => write!(
                formatter,
                "kata's ChatGPT login at {} is expired and its refresh did not renew it; run \
                 `kata login openai`",
                path.display()
            ),
            Self::Harness { path, source } => write!(
                formatter,
                "kata's ChatGPT login at {} cannot be used ({source}); run `kata login openai`",
                path.display()
            ),
            Self::Login(source) => {
                write!(formatter, "the ChatGPT login did not complete: {source}")
            }
            Self::DeviceLogin(failure) => write!(
                formatter,
                "the ChatGPT device-code login did not complete, and nothing was stored: \
                 {failure}"
            ),
        }
    }
}

impl std::error::Error for KataLoginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Harness { source, .. }
            | Self::DeviceLogin(DeviceLoginFailure::Harness(source)) => Some(source),
            Self::Login(source) => Some(source),
            Self::DeviceLogin(_)
            | Self::ModeUnavailable { .. }
            | Self::Absent { .. }
            | Self::Insecure { .. }
            | Self::Malformed { .. }
            | Self::KeyRefused { .. }
            | Self::NotSignedIn { .. }
            | Self::Expired { .. } => None,
        }
    }
}

/// The token issuer a ChatGPT login refreshes against: nanocode's own default
/// (OpenAI's), or, under `test-support` only, a mock on loopback. No
/// production config key names an issuer.
#[derive(Clone, Debug, Default)]
pub struct Issuer {
    #[cfg(feature = "test-support")]
    local: Option<std::sync::Arc<str>>,
}

impl Issuer {
    /// A mock issuer at `http://127.0.0.1:<port>` (nanocode admits no other
    /// override).
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn local_for_test(url: &str) -> Self {
        Self {
            local: Some(std::sync::Arc::from(url)),
        }
    }

    async fn open(
        &self,
        store: impl ChatGptSubscriptionHost,
        seed: Option<ChatGptCredentialSeed>,
    ) -> Result<ChatGptSubscription, ChatGptSubscriptionError> {
        #[cfg(feature = "test-support")]
        if let Some(url) = &self.local {
            return ChatGptSubscription::open_with_issuer(
                store,
                CHATGPT_KEY,
                seed,
                std::sync::Arc::clone(url),
            )
            .await;
        }
        ChatGptSubscription::open(store, CHATGPT_KEY, seed).await
    }
}

/// Check the logins directory: a real directory (not a symlink), owned by the
/// effective uid, with no group or world bits.
///
/// # Errors
/// [`KataLoginError::Absent`] (naming `file`, whose login creates the
/// directory) when it does not exist; [`KataLoginError::Insecure`] otherwise.
pub fn check_logins_dir(dir: &Path, file: LoginFile) -> Result<(), KataLoginError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(KataLoginError::Absent {
                file,
                path: dir.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(KataLoginError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    let insecure = |reason: String| KataLoginError::Insecure {
        path: dir.to_path_buf(),
        reason,
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(insecure(
            "it must be a real directory, not a symlink".into(),
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    if metadata.uid() != euid {
        return Err(insecure(foreign_owner_refusal(metadata.uid(), euid)));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(insecure(format!(
            "its mode is {mode:o}; it must have no group or world bits; {}",
            chmod_fix("700", dir)
        )));
    }
    Ok(())
}

/// Check one login file: a regular file (not a symlink) with one link, owned
/// by the effective uid, with no group or world bits.
///
/// # Errors
/// [`KataLoginError::Absent`] when it does not exist;
/// [`KataLoginError::Insecure`] otherwise.
pub fn check_login_file(path: &Path, file: LoginFile) -> Result<(), KataLoginError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(KataLoginError::Absent {
                file,
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(KataLoginError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let insecure = |reason: String| KataLoginError::Insecure {
        path: path.to_path_buf(),
        reason,
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(insecure("it must be a regular file, not a symlink".into()));
    }
    if metadata.nlink() != 1 {
        return Err(insecure(format!(
            "it has {} links; it must have exactly one",
            metadata.nlink()
        )));
    }
    let euid = rustix::process::geteuid().as_raw();
    if metadata.uid() != euid {
        return Err(insecure(foreign_owner_refusal(metadata.uid(), euid)));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(insecure(format!(
            "its mode is {mode:o}; it must have no group or world bits; {}",
            chmod_fix("600", path)
        )));
    }
    Ok(())
}

/// Why a login path another account owns is refused. kata never proposes
/// taking it over, so the refusal names no command.
fn foreign_owner_refusal(owner: u32, euid: u32) -> String {
    format!(
        "refused: uid {owner} owns it, not you (uid {euid}); kata keeps a login only where no other account can read or replace it"
    )
}

/// `fix: chmod <mode> <path>`, the path one POSIX shell word, so the printed
/// command is the one to run (the checks read only the permission bits, so
/// a plain numeric mode is exact). A path that is not UTF-8 cannot be printed
/// exactly, so it gets the instruction without a command.
fn chmod_fix(mode: &str, path: &Path) -> String {
    match path.to_str().map(shlex::try_quote) {
        Some(Ok(word)) => format!("fix: chmod {mode} {word}"),
        _ => format!(
            "fix by hand: chmod {mode} on this path (it is not UTF-8, so no command is printed)"
        ),
    }
}

/// Check the directory, then the file.
fn check_file(dir: &Path, file: LoginFile) -> Result<PathBuf, KataLoginError> {
    check_logins_dir(dir, file)?;
    let path = file.path(dir);
    check_login_file(&path, file)?;
    Ok(path)
}

/// A loaded harness credential and the values every adapter-influenced string
/// is scrubbed of.
pub struct LoadedLogin {
    /// The adapter's carrier.
    pub auth: HarnessAuth,
    /// The secret values this load handed out: the API key, or the access
    /// token current at load. A token a later refresh mints is not in it.
    pub scrub: Vec<String>,
}

impl std::fmt::Debug for LoadedLogin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedLogin")
            .field("auth", &self.auth)
            .field("scrub", &format_args!("<{} redacted>", self.scrub.len()))
            .finish()
    }
}

/// Load kata's own login for a turn of `kind` declared under `mode`, from
/// `logins_dir` and nothing else.
///
/// The directory and the file are checked first ([`check_logins_dir`],
/// [`check_login_file`]). An API key is read whole. A ChatGPT login is opened
/// through nanocode over [`FileStore`]: an access token inside nanocode's
/// refresh window is refreshed HERE, before the container exists, and a token
/// already past its expiry after that refresh is refused.
///
/// # Errors
/// [`KataLoginError`]; [`KataLoginError::refusal`] names the refusal.
pub fn load(
    logins_dir: &Path,
    kind: AdapterKind,
    mode: CredentialMode,
    issuer: &Issuer,
) -> Result<LoadedLogin, KataLoginError> {
    let provider = LoginProvider::of_kind(kind);
    let file = provider
        .file(mode)
        .ok_or(KataLoginError::ModeUnavailable { provider, mode })?;
    let path = check_file(logins_dir, file)?;
    match file {
        LoginFile::OpenAiApiKey | LoginFile::AnthropicApiKey => {
            let key = read_api_key(&path)?;
            let auth = HarnessAuth::api_key(kind, key.clone());
            Ok(LoadedLogin {
                auth,
                scrub: vec![key],
            })
        }
        LoginFile::OpenAiChatGpt => {
            let store = FileStore::new(path.clone());
            let issuer = issuer.clone();
            on_own_runtime(load_chatgpt(store, issuer, path))
        }
    }
}

async fn load_chatgpt(
    store: FileStore,
    issuer: Issuer,
    path: PathBuf,
) -> Result<LoadedLogin, KataLoginError> {
    let harness = |source| KataLoginError::Harness {
        path: path.clone(),
        source,
    };
    let subscription = issuer.open(store, None).await.map_err(harness)?;
    if !matches!(
        subscription.status().await.map_err(harness)?,
        ChatGptLoginStatus::Authenticated { .. }
    ) {
        return Err(KataLoginError::NotSignedIn { path });
    }
    // Refreshes an access token inside nanocode's early window; a failed
    // refresh is logged by nanocode and the stale token kept. Only a token
    // already past its expiry is refused: one still live (a transient refresh
    // failure inside the window) is handed out, and nanocode refreshes again
    // mid-turn. kata keeps no copy of nanocode's private window, so a nanocode
    // bump that moves it cannot open a gap kata refuses.
    let auth = subscription.authorization().await.map_err(harness)?;
    if let ChatGptLoginStatus::Authenticated {
        expires_at: Some(expires_at),
        ..
    } = subscription.status().await.map_err(harness)?
        && expires_at <= now_ms()
    {
        return Err(KataLoginError::Expired { path });
    }
    let current = subscription.credential().await.map_err(harness)?;
    Ok(LoadedLogin {
        auth: HarnessAuth::OpenAi(auth),
        scrub: vec![current.access_token().to_owned()],
    })
}

/// Run `future` to completion on a runtime of its own, on a thread of its own:
/// the caller may be synchronous, or a blocking thread of another runtime, and
/// neither may block on a runtime it does not own.
///
/// The runtime is shut down in the BACKGROUND once `future` answers: a
/// [`FileStore::lock`] wait that timed out leaves its `flock` thread parked on
/// the other holder's lock, and a plain drop of the runtime would join that
/// thread, returning only when the holder lets go
/// (`a_lock_held_past_the_wait_refuses_at_the_wait`).
fn on_own_runtime<T: Send>(
    future: impl std::future::Future<Output = Result<T, KataLoginError>> + Send,
) -> Result<T, KataLoginError> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|source| KataLoginError::Io {
                        path: PathBuf::new(),
                        source,
                    })?;
                let answer = runtime.block_on(future);
                runtime.shutdown_background();
                answer
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

/// Read an API key file: one line, the trailing newline dropped.
fn read_api_key(path: &Path) -> Result<String, KataLoginError> {
    let bytes = std::fs::read(path).map_err(|source| KataLoginError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| KataLoginError::Malformed {
        path: path.to_path_buf(),
        detail: "not UTF-8".into(),
    })?;
    let key = text.strip_suffix('\n').unwrap_or(&text);
    validate_api_key(key).map_err(|detail| KataLoginError::Malformed {
        path: path.to_path_buf(),
        detail,
    })?;
    Ok(key.to_owned())
}

/// An API key kata stores: non-empty, with no whitespace or control character.
fn validate_api_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("the key is empty".into());
    }
    if key.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the key holds whitespace or a control character".into());
    }
    Ok(())
}

/// Create the logins directory (and its parents) owner-only, or check the one
/// that exists.
///
/// # Errors
/// [`KataLoginError::Io`] when it cannot be created; the
/// [`check_logins_dir`] refusals otherwise.
pub fn ensure_logins_dir(dir: &Path, file: LoginFile) -> Result<(), KataLoginError> {
    use std::os::unix::fs::DirBuilderExt as _;

    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(source) => {
            return Err(KataLoginError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    }
    check_logins_dir(dir, file)
}

/// Store an API key for `file`'s provider, replacing any earlier one.
///
/// # Errors
/// [`KataLoginError::KeyRefused`] for a key kata would not store (before any
/// directory or file is created);
/// [`ensure_logins_dir`]'s refusals; [`KataLoginError::Io`].
pub fn store_api_key(logins_dir: &Path, file: LoginFile, key: &str) -> Result<(), KataLoginError> {
    if file.mode() != CredentialMode::ApiKey {
        return Err(KataLoginError::KeyRefused {
            file,
            detail: "this login file holds no API key".into(),
        });
    }
    validate_api_key(key).map_err(|detail| KataLoginError::KeyRefused { file, detail })?;
    let path = file.path(logins_dir);
    ensure_logins_dir(logins_dir, file)?;
    sweep_crashed_copies(logins_dir, file)?;
    write_owner_only(&path, format!("{key}\n").as_bytes())
}

/// Whether `name` is the temporary copy [`write_owner_only`] creates for
/// `file`: exactly `.<file name>.<digits>.<digits>.tmp`.
fn is_crashed_copy(name: &str, file: LoginFile) -> bool {
    let Some(middle) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_prefix(file.file_name()))
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    middle
        .split_once('.')
        .is_some_and(|(pid, ms)| digits(pid) && digits(ms))
}

/// Remove every temporary copy of `file` in `logins_dir`: a write that died
/// between creating its `.<file>.<pid>.<ms>.tmp` and renaming it left a full
/// owner-only copy of the credential that no [`LoginFile`] names. Returns the
/// paths removed.
///
/// Called before each write of `file` and by [`logout`]. The ChatGPT store is
/// written only under its lock, and both callers hold it there, so no live
/// write of it can lose its copy. An API-key write takes no lock: a
/// concurrent `kata login --api-key` of the same file can lose its copy to
/// this sweep, and then refuses with the rename's I/O error, leaving the
/// file whole.
fn sweep_crashed_copies(
    logins_dir: &Path,
    file: LoginFile,
) -> Result<Vec<PathBuf>, KataLoginError> {
    let io = |source| KataLoginError::Io {
        path: logins_dir.to_path_buf(),
        source,
    };
    let entries = match std::fs::read_dir(logins_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io(error)),
    };
    let mut removed = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io)?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| is_crashed_copy(name, file))
        {
            continue;
        }
        let path = entry.path();
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(KataLoginError::Io { path, source }),
        }
    }
    Ok(removed)
}

/// Write `bytes` to `path` whole: a new 0600 temporary file in the same
/// directory, synced, renamed over `path`, then the directory synced.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), KataLoginError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let io = |source| KataLoginError::Io {
        path: path.to_path_buf(),
        source,
    };
    let dir = path.parent().ok_or_else(|| KataLoginError::Malformed {
        path: path.to_path_buf(),
        detail: "the path has no directory".into(),
    })?;
    let name = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let temporary = dir.join(format!(".{name}.{}.{}.tmp", std::process::id(), now_ms()));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io)?;
    if let Err(error) = out.write_all(bytes).and_then(|()| out.sync_all()) {
        drop(out);
        let _ = std::fs::remove_file(&temporary);
        return Err(io(error));
    }
    drop(out);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io(error));
    }
    File::open(dir).and_then(|dir| dir.sync_all()).map_err(io)
}

/// What the ChatGPT store's file holds: nanocode's state, kept opaque, under
/// kata's revision counter.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    revision: u64,
    state: String,
}

/// kata's implementation of nanocode's `ChatGptSubscriptionHost`: one store
/// file, compare-and-swap under an exclusive `flock`, and the issuer reached
/// over kata's own HTTP client, with every refresh serialized as the module
/// doc states.
pub struct FileStore {
    path: PathBuf,
    lock_path: PathBuf,
    /// The lock a refresh took and keeps until nanocode commits its answer.
    held: Mutex<Option<File>>,
    /// How long [`Self::lock`] waits: [`LOCK_WAIT`], shortened only by the
    /// lock-wait cell so it need not pay the real minute.
    lock_wait: Duration,
}

impl FileStore {
    fn new(path: PathBuf) -> Self {
        let mut lock_path = path.clone().into_os_string();
        lock_path.push(".lock");
        Self {
            path,
            lock_path: PathBuf::from(lock_path),
            held: Mutex::new(None),
            lock_wait: LOCK_WAIT,
        }
    }

    fn host_error(&self, what: &str, error: impl std::fmt::Display) -> SubscriptionHostError {
        SubscriptionHostError::new(format!("{what} {}: {error}", self.path.display()))
    }

    fn check_key(&self, key: &str) -> Result<(), SubscriptionHostError> {
        if key == CHATGPT_KEY {
            Ok(())
        } else {
            Err(self.host_error("store", format!("serves only `{CHATGPT_KEY}`, not `{key}`")))
        }
    }

    /// Read the store; an absent file is revision 0 with no state.
    fn read(&self) -> Result<SubscriptionStoreValue, SubscriptionHostError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(SubscriptionStoreValue::default());
            }
            Err(error) => return Err(self.host_error("reading", error)),
        };
        let stored: StoredState =
            serde_json::from_slice(&bytes).map_err(|error| self.host_error("parsing", error))?;
        Ok(SubscriptionStoreValue {
            revision: stored.revision,
            payload: Some(stored.state),
        })
    }

    /// The refresh token the stored state holds, if any.
    fn stored_refresh_token(&self) -> Result<Option<String>, SubscriptionHostError> {
        let Some(payload) = self.read()?.payload else {
            return Ok(None);
        };
        let state: serde_json::Value =
            serde_json::from_str(&payload).map_err(|error| self.host_error("parsing", error))?;
        Ok(state
            .pointer("/credential/refresh_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned))
    }

    /// Take the exclusive lock, waiting at most [`LOCK_WAIT`]. The wait is the
    /// kernel's (a blocking `flock` on a blocking thread), so a waiter wakes the
    /// moment the holder releases, never a poll interval later. A wait that
    /// times out answers its caller at the timeout and leaves its thread
    /// blocked until the holder releases ([`on_own_runtime`] does not join
    /// it); the thread then takes the lock and drops it at once, answering no
    /// one.
    async fn lock(&self) -> Result<File, SubscriptionHostError> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let lock_path = self.lock_path.clone();
        let waiting = tokio::task::spawn_blocking(move || -> std::io::Result<File> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&lock_path)?;
            file.lock()?;
            Ok(file)
        });
        match tokio::time::timeout(self.lock_wait, waiting).await {
            Ok(joined) => joined
                .map_err(|error| self.host_error("locking", error))?
                .map_err(|error| self.host_error("locking", error)),
            Err(_) => Err(self.host_error(
                "locking",
                format!(
                    "another holder kept the login's lock past {:?}",
                    self.lock_wait
                ),
            )),
        }
    }

    fn take_held(&self) -> Option<File> {
        self.held.lock().ok().and_then(|mut held| held.take())
    }

    fn keep_held(&self, lock: File) {
        if let Ok(mut held) = self.held.lock() {
            *held = Some(lock);
        }
    }

    async fn compare_and_swap_locked(
        &self,
        expected_revision: u64,
        payload: &str,
    ) -> Result<SubscriptionCommit, SubscriptionHostError> {
        let lock = match self.take_held() {
            Some(lock) => lock,
            None => self.lock().await?,
        };
        let current = self.read()?.revision;
        if current != expected_revision {
            drop(lock);
            return Ok(SubscriptionCommit::Conflict(current));
        }
        let next = expected_revision.wrapping_add(1);
        let bytes = serde_json::to_vec(&StoredState {
            revision: next,
            state: payload.to_owned(),
        })
        .map_err(|error| self.host_error("encoding", error))?;
        if let Some(dir) = self.path.parent() {
            sweep_crashed_copies(dir, LoginFile::OpenAiChatGpt)
                .map_err(|error| self.host_error("sweeping", error))?;
        }
        write_owner_only(&self.path, &bytes).map_err(|error| self.host_error("writing", error))?;
        drop(lock);
        Ok(SubscriptionCommit::Committed(next))
    }

    async fn request_serialized(
        &self,
        request: SubscriptionHttpRequest,
    ) -> Result<SubscriptionHttpResponse, SubscriptionHostError> {
        let Some(presented) = refresh_token_presented(&request) else {
            return self.send(&request).await;
        };
        // A lock still held by an earlier refresh of this store whose answer
        // was never committed is released before this one waits.
        drop(self.take_held());
        let lock = self.lock().await?;
        if self.stored_refresh_token()?.as_deref() != Some(presented.as_str()) {
            drop(lock);
            return Ok(SubscriptionHttpResponse {
                status: SUPERSEDED_STATUS,
                body: SUPERSEDED_BODY.to_owned(),
            });
        }
        let response = self.send(&request).await?;
        if (200..300).contains(&response.status) {
            self.keep_held(lock);
        }
        Ok(response)
    }

    async fn send(
        &self,
        request: &SubscriptionHttpRequest,
    ) -> Result<SubscriptionHttpResponse, SubscriptionHostError> {
        send_to_issuer(request)
            .await
            .map_err(|(what, error)| self.host_error(what, error))
    }
}

/// One issuer round trip over kata's own HTTP client, bounded by
/// [`ISSUER_TIMEOUT`] and by the request's response-size limit. A failure is
/// `(what failed, why)`; the caller names the store it was for.
async fn send_to_issuer(
    request: &SubscriptionHttpRequest,
) -> Result<SubscriptionHttpResponse, (&'static str, String)> {
    nanocode_backend_codex::client::transport::install_default_rustls_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(ISSUER_TIMEOUT)
        .build()
        .map_err(|error| ("building the issuer client for", error.to_string()))?;
    let method = reqwest::Method::from_bytes(request.method().as_bytes())
        .map_err(|error| ("issuer method for", error.to_string()))?;
    let mut response = client
        .request(method, request.url())
        .header(reqwest::header::CONTENT_TYPE, request.content_type())
        .body(request.body().to_owned())
        .send()
        .await
        .map_err(|error| ("the issuer request for", error.to_string()))?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ("the issuer response for", error.to_string()))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > request.max_response_bytes() {
            return Err((
                "the issuer response for",
                format!("exceeds {} bytes", request.max_response_bytes()),
            ));
        }
    }
    let body =
        String::from_utf8(body).map_err(|error| ("the issuer response for", error.to_string()))?;
    Ok(SubscriptionHttpResponse { status, body })
}

/// The refresh token a refresh-grant request presents; `None` for any other
/// request.
fn refresh_token_presented(request: &SubscriptionHttpRequest) -> Option<String> {
    if request.content_type() != "application/json" {
        return None;
    }
    let body: serde_json::Value = serde_json::from_str(request.body()).ok()?;
    if body.get("grant_type")?.as_str()? != "refresh_token" {
        return None;
    }
    body.get("refresh_token")?.as_str().map(str::to_owned)
}

impl ChatGptSubscriptionHost for FileStore {
    fn load<'a>(
        &'a self,
        key: &'a str,
    ) -> SubscriptionFuture<'a, Result<SubscriptionStoreValue, SubscriptionHostError>> {
        Box::pin(async move {
            self.check_key(key)?;
            self.read()
        })
    }

    fn compare_and_swap<'a>(
        &'a self,
        key: &'a str,
        expected_revision: u64,
        payload: &'a str,
    ) -> SubscriptionFuture<'a, Result<SubscriptionCommit, SubscriptionHostError>> {
        Box::pin(async move {
            self.check_key(key)?;
            self.compare_and_swap_locked(expected_revision, payload)
                .await
        })
    }

    fn request(
        &self,
        request: SubscriptionHttpRequest,
    ) -> SubscriptionFuture<'_, Result<SubscriptionHttpResponse, SubscriptionHostError>> {
        Box::pin(self.request_serialized(request))
    }
}

/// Run the ChatGPT browser login and store its result as kata's login,
/// replacing any earlier one.
///
/// nanocode's `ChatGptLogin` (PKCE, a loopback callback on localhost 1455 or
/// 1457, five minutes) writes its answer to a staging file inside the logins
/// directory; kata seeds its own store from it and removes it.
/// `on_authorization_url` receives the URL the operator opens.
///
/// # Errors
/// [`KataLoginError::Login`] when the login does not complete;
/// [`ensure_logins_dir`]'s and the store's refusals.
pub async fn login_openai_chatgpt(
    logins_dir: &Path,
    on_authorization_url: impl FnOnce(&str),
) -> Result<ChatGptAccount, KataLoginError> {
    ensure_logins_dir(logins_dir, LoginFile::OpenAiChatGpt)?;
    let staging = chatgpt_staging(logins_dir);
    remove_staging(&staging);
    let result = async {
        let login = ChatGptLogin::start(&staging)
            .await
            .map_err(KataLoginError::Login)?;
        on_authorization_url(login.authorization_url());
        login.complete().await.map_err(KataLoginError::Login)?;
        let seed = seed_from_codex_document(&staging)?;
        store_seed(logins_dir, seed, &Issuer::default()).await
    }
    .await;
    remove_staging(&staging);
    result
}

/// The account a ChatGPT login is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatGptAccount {
    /// The ChatGPT account id.
    pub account_id: String,
}

/// Where the browser login's `ChatGptLogin` writes its answer: a codex
/// `auth.json` document, refresh token included, that no [`LoginFile`] names.
fn chatgpt_staging(logins_dir: &Path) -> PathBuf {
    logins_dir.join("openai-chatgpt.login.json")
}

fn remove_staging(staging: &Path) {
    let mut lock = staging.as_os_str().to_os_string();
    lock.push(".lock");
    for path in [staging.to_path_buf(), PathBuf::from(lock)] {
        let _ = std::fs::remove_file(path);
    }
}

/// The seed a completed browser login's staging file yields: nanocode's
/// ChatGPT document (the codex `auth.json` shape), which `ChatGptLogin`
/// wrote and kata reads only from the staging path it named.
fn seed_from_codex_document(staging: &Path) -> Result<ChatGptCredentialSeed, KataLoginError> {
    let malformed = |detail: String| KataLoginError::Malformed {
        path: staging.to_path_buf(),
        detail,
    };
    let status = nanocode_backend_codex::client::auth::chatgpt_auth_status(staging)
        .map_err(KataLoginError::Login)?;
    let bytes = std::fs::read(staging).map_err(|source| KataLoginError::Io {
        path: staging.to_path_buf(),
        source,
    })?;
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| malformed(error.to_string()))?;
    let token = |name: &str| {
        document
            .pointer(&format!("/tokens/{name}"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| malformed(format!("no `tokens.{name}`")))
    };
    Ok(ChatGptCredentialSeed::new(
        token("access_token")?,
        token("refresh_token")?,
        status.account_id,
        status.fedramp,
    ))
}

/// What the operator enters where to complete a device-code login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCode {
    /// The page the operator opens, on any device.
    pub verification_url: String,
    /// The one-time code the operator types there. It authorizes nothing by
    /// itself: the tokens are minted only to this process's poll.
    pub user_code: String,
    /// When the issuer stops accepting the code, Unix milliseconds.
    pub expires_at_ms: i64,
}

/// One of the device login's issuer requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStep {
    /// `POST /api/accounts/deviceauth/usercode`: the code is issued.
    UserCode,
    /// `POST /api/accounts/deviceauth/token`: the poll for the operator's
    /// approval.
    TokenPoll,
    /// `POST /oauth/token`: the approval's authorization code is exchanged for
    /// the login's tokens.
    CodeExchange,
}

impl DeviceStep {
    const PATHS: [(&'static str, Self); 3] = [
        ("/api/accounts/deviceauth/usercode", Self::UserCode),
        ("/api/accounts/deviceauth/token", Self::TokenPoll),
        ("/oauth/token", Self::CodeExchange),
    ];

    fn of_url(url: &str) -> Option<Self> {
        Self::PATHS
            .into_iter()
            .find_map(|(path, step)| url.ends_with(path).then_some(step))
    }

    /// The step's name in a refusal.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::UserCode => "the device-code request",
            Self::TokenPoll => "the approval poll",
            Self::CodeExchange => "the token exchange",
        }
    }

    /// The refusal an issuer answer of `status` to this step is, if any. The
    /// poll's `403` and `404` mean "not approved yet", as codex reads them; a
    /// `404` to the code request means the issuer has no device-code login.
    fn refusal(self, status: u16) -> Option<DeviceLoginFailure> {
        match (self, status) {
            (_, 200..=299) | (Self::TokenPoll, 403 | 404) => None,
            (Self::UserCode, 404) => Some(DeviceLoginFailure::NotEnabled),
            (step, status) => Some(DeviceLoginFailure::Refused { step, status }),
        }
    }
}

/// Why a device-code login stored nothing.
#[derive(Clone, Debug)]
pub enum DeviceLoginFailure {
    /// The issuer answered the code request `404`: it offers no device-code
    /// login to this client.
    NotEnabled,
    /// The issuer answered a step with an error status.
    Refused {
        /// The step.
        step: DeviceStep,
        /// The HTTP status.
        status: u16,
    },
    /// The code expired before the operator approved it.
    Expired,
    /// The operator interrupted the wait.
    Interrupted,
    /// nanocode refused the issuer's answer, or its transport failed.
    Harness(ChatGptSubscriptionError),
}

impl std::fmt::Display for DeviceLoginFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnabled => write!(
                formatter,
                "device_code_not_enabled: the issuer answered HTTP 404 to {}, which codex \
                 reports as \"device code login is not enabled for this Codex server. Use the \
                 browser login or verify the server URL.\"; log in with `kata login openai \
                 --browser` instead",
                DeviceStep::UserCode.as_label()
            ),
            Self::Refused { step, status } => write!(
                formatter,
                "device_code_refused: the issuer answered HTTP {status} to {}",
                step.as_label()
            ),
            Self::Expired => write!(
                formatter,
                "device_code_expired: the code was not approved before it expired"
            ),
            Self::Interrupted => write!(
                formatter,
                "device_code_interrupted: the wait was interrupted"
            ),
            Self::Harness(source) => write!(formatter, "device_code_failed: {source}"),
        }
    }
}

/// The device login's store: nanocode's pending device authorization and the
/// credential it mints, held in THIS process's memory only. No login file is
/// touched until the login has completed, so a refused, expired or
/// interrupted login writes no file: an earlier login stays byte-for-byte as
/// it was, and an absent logins directory is at most created, empty and 0700
/// (`login_device_code_on` ensures it before the flow starts). (nanocode's
/// `start_login` clears the store it runs on, so running it on kata's own
/// store would lose the earlier login at the first step.)
///
/// Every issuer answer passes through [`ChatGptSubscriptionHost::request`]
/// here, which records the first one that is a refusal ([`DeviceStep`]), so the
/// login is refused by the issuer's status rather than by nanocode's prose.
#[derive(Clone, Default)]
struct DeviceStore {
    value: std::sync::Arc<Mutex<SubscriptionStoreValue>>,
    refusal: std::sync::Arc<Mutex<Option<DeviceLoginFailure>>>,
}

impl DeviceStore {
    fn check_key(key: &str) -> Result<(), SubscriptionHostError> {
        if key == CHATGPT_KEY {
            Ok(())
        } else {
            Err(SubscriptionHostError::new(format!(
                "the device login's store serves only `{CHATGPT_KEY}`, not `{key}`"
            )))
        }
    }

    fn value(&self) -> SubscriptionStoreValue {
        self.value.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |value| value.clone(),
        )
    }

    /// The refusal the issuer answered, else nanocode's own error.
    fn failure(&self, source: ChatGptSubscriptionError) -> DeviceLoginFailure {
        self.refusal
            .lock()
            .ok()
            .and_then(|refusal| refusal.clone())
            .unwrap_or(DeviceLoginFailure::Harness(source))
    }

    /// The credential nanocode committed here, as the seed the browser login's
    /// staging file also yields: the same four fields, so both flows store the
    /// same login through [`store_seed`].
    fn seed(&self) -> Result<ChatGptCredentialSeed, DeviceLoginFailure> {
        let invalid = |detail: &str| {
            DeviceLoginFailure::Harness(ChatGptSubscriptionError::Invalid(std::sync::Arc::from(
                format!("the completed device login {detail}"),
            )))
        };
        let payload = self
            .value()
            .payload
            .ok_or_else(|| invalid("left no state"))?;
        let state: serde_json::Value =
            serde_json::from_str(&payload).map_err(|_| invalid("left state that is not JSON"))?;
        let text = |name: &str| {
            state
                .pointer(&format!("/credential/{name}"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("holds no `credential.{name}`")))
        };
        let fedramp = state
            .pointer("/credential/fedramp")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| invalid("holds no `credential.fedramp`"))?;
        Ok(ChatGptCredentialSeed::new(
            text("access_token")?,
            text("refresh_token")?,
            text("account_id")?,
            fedramp,
        ))
    }
}

impl ChatGptSubscriptionHost for DeviceStore {
    fn load<'a>(
        &'a self,
        key: &'a str,
    ) -> SubscriptionFuture<'a, Result<SubscriptionStoreValue, SubscriptionHostError>> {
        Box::pin(async move {
            Self::check_key(key)?;
            Ok(self.value())
        })
    }

    fn compare_and_swap<'a>(
        &'a self,
        key: &'a str,
        expected_revision: u64,
        payload: &'a str,
    ) -> SubscriptionFuture<'a, Result<SubscriptionCommit, SubscriptionHostError>> {
        Box::pin(async move {
            Self::check_key(key)?;
            let mut value = self
                .value
                .lock()
                .map_err(|_| SubscriptionHostError::new("the device login's store is poisoned"))?;
            if value.revision != expected_revision {
                return Ok(SubscriptionCommit::Conflict(value.revision));
            }
            value.revision = expected_revision.wrapping_add(1);
            value.payload = Some(payload.to_owned());
            Ok(SubscriptionCommit::Committed(value.revision))
        })
    }

    fn request(
        &self,
        request: SubscriptionHttpRequest,
    ) -> SubscriptionFuture<'_, Result<SubscriptionHttpResponse, SubscriptionHostError>> {
        Box::pin(async move {
            let response = send_to_issuer(&request).await.map_err(|(what, error)| {
                SubscriptionHostError::new(format!("{what} the device login: {error}"))
            })?;
            if let Some(refusal) =
                DeviceStep::of_url(request.url()).and_then(|step| step.refusal(response.status))
                && let Ok(mut recorded) = self.refusal.lock()
            {
                recorded.get_or_insert(refusal);
            }
            Ok(response)
        })
    }
}

/// Run the ChatGPT device-code login and store its result as kata's login,
/// replacing any earlier one: the same file, through the same [`store_seed`],
/// as [`login_openai_chatgpt`].
///
/// nanocode's `ChatGptSubscription` drives the issuer's device authorization
/// (codex's own: a code from `/api/accounts/deviceauth/usercode`, polled at
/// `/api/accounts/deviceauth/token` at the issuer's interval, the approval
/// exchanged at `/oauth/token`) over a [`DeviceStore`] in memory.
/// `on_code` receives the URL and code the operator enters. The wait ends at
/// the approval, a refusal, the code's expiry, or `interrupted`; only the
/// approval writes a file.
///
/// # Errors
/// [`KataLoginError::DeviceLogin`] when the login does not complete;
/// [`ensure_logins_dir`]'s and the store's refusals.
pub async fn login_openai_device_code(
    logins_dir: &Path,
    issuer: &Issuer,
    on_code: impl FnOnce(&DeviceCode),
    interrupted: impl std::future::Future<Output = ()>,
) -> Result<ChatGptAccount, KataLoginError> {
    login_device_code_on(
        DeviceStore::default(),
        logins_dir,
        issuer,
        on_code,
        interrupted,
    )
    .await
}

async fn login_device_code_on(
    store: DeviceStore,
    logins_dir: &Path,
    issuer: &Issuer,
    on_code: impl FnOnce(&DeviceCode),
    interrupted: impl std::future::Future<Output = ()>,
) -> Result<ChatGptAccount, KataLoginError> {
    ensure_logins_dir(logins_dir, LoginFile::OpenAiChatGpt)?;
    let seed = tokio::select! {
        seed = approve_device_code(store, issuer, on_code) => seed,
        () = interrupted => Err(DeviceLoginFailure::Interrupted),
    }
    .map_err(KataLoginError::DeviceLogin)?;
    store_seed(logins_dir, seed, issuer).await
}

/// Issue a code, hand it to `on_code`, and poll until the issuer answers.
async fn approve_device_code(
    store: DeviceStore,
    issuer: &Issuer,
    on_code: impl FnOnce(&DeviceCode),
) -> Result<ChatGptCredentialSeed, DeviceLoginFailure> {
    let subscription = issuer
        .open(store.clone(), None)
        .await
        .map_err(|source| store.failure(source))?;
    let mut status = subscription
        .start_login()
        .await
        .map_err(|source| store.failure(source))?;
    let ChatGptLoginStatus::Pending {
        verification_url,
        user_code,
        expires_at,
        ..
    } = &status
    else {
        return Err(DeviceLoginFailure::Harness(
            ChatGptSubscriptionError::Invalid(std::sync::Arc::from(
                "the device login issued no code",
            )),
        ));
    };
    on_code(&DeviceCode {
        verification_url: verification_url.clone(),
        user_code: user_code.clone(),
        expires_at_ms: *expires_at,
    });
    loop {
        match status {
            // nanocode answers the wait the issuer's interval leaves before
            // its next poll, and polls at most once per call.
            ChatGptLoginStatus::Pending { poll_after_ms, .. } => {
                tokio::time::sleep(Duration::from_millis(
                    u64::try_from(poll_after_ms).unwrap_or(0),
                ))
                .await;
            }
            ChatGptLoginStatus::Authenticated { .. } => return store.seed(),
            ChatGptLoginStatus::Expired => return Err(DeviceLoginFailure::Expired),
            ChatGptLoginStatus::SignedOut => {
                return Err(DeviceLoginFailure::Harness(
                    ChatGptSubscriptionError::NotAuthenticated,
                ));
            }
        }
        status = subscription
            .status()
            .await
            .map_err(|source| store.failure(source))?;
    }
}

/// Replace kata's ChatGPT store with `seed`.
async fn store_seed(
    logins_dir: &Path,
    seed: ChatGptCredentialSeed,
    issuer: &Issuer,
) -> Result<ChatGptAccount, KataLoginError> {
    let path = LoginFile::OpenAiChatGpt.path(logins_dir);
    let harness = |source| KataLoginError::Harness {
        path: path.clone(),
        source,
    };
    // Clear the earlier login first: nanocode keeps a stored credential over a
    // seed (it repairs only one with no refresh token).
    issuer
        .open(FileStore::new(path.clone()), None)
        .await
        .map_err(harness)?
        .logout()
        .await
        .map_err(harness)?;
    let subscription = issuer
        .open(FileStore::new(path.clone()), Some(seed))
        .await
        .map_err(harness)?;
    match subscription.status().await.map_err(harness)? {
        ChatGptLoginStatus::Authenticated { account_id, .. } => Ok(ChatGptAccount { account_id }),
        _ => Err(KataLoginError::NotSignedIn { path }),
    }
}

/// Seed kata's ChatGPT store directly — the cells' door to a stored login
/// without a browser.
///
/// # Errors
/// As [`login_openai_chatgpt`] after the browser half.
#[cfg(feature = "test-support")]
pub fn store_chatgpt_seed_for_test(
    logins_dir: &Path,
    access_token: &str,
    refresh_token: &str,
    account_id: &str,
    issuer: &Issuer,
) -> Result<ChatGptAccount, KataLoginError> {
    ensure_logins_dir(logins_dir, LoginFile::OpenAiChatGpt)?;
    let seed = ChatGptCredentialSeed::new(access_token, refresh_token, account_id, false);
    let issuer = issuer.clone();
    on_own_runtime(async move { store_seed(logins_dir, seed, &issuer).await })
}

/// What `kata login status` and `kata doctor` report about one login file,
/// read offline: no issuer is contacted and nothing is refreshed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginState {
    /// The file does not exist.
    Absent,
    /// The directory or the file fails the owner-only check.
    Insecure(String),
    /// The file is not what kata wrote.
    Malformed(String),
    /// An API key is stored.
    ApiKey,
    /// The ChatGPT store.
    ChatGpt {
        /// The account a completed login is for; `None` when no login completed.
        account_id: Option<String>,
        /// The access token's expiry, in Unix milliseconds, when it states one.
        access_expires_at_ms: Option<i64>,
        /// Whether a non-empty refresh token is stored.
        refresh_token: bool,
        /// The store's revision (one per committed change).
        revision: u64,
    },
}

/// The offline state of `file` in `logins_dir`.
#[must_use]
pub fn login_state(logins_dir: &Path, file: LoginFile) -> LoginState {
    let path = match check_file(logins_dir, file) {
        Ok(path) => path,
        Err(KataLoginError::Absent { .. }) => return LoginState::Absent,
        Err(KataLoginError::Insecure { path, reason }) => {
            return LoginState::Insecure(format!("{}: {reason}", path.display()));
        }
        Err(error) => return LoginState::Malformed(error.to_string()),
    };
    match file {
        LoginFile::OpenAiApiKey | LoginFile::AnthropicApiKey => match read_api_key(&path) {
            Ok(_) => LoginState::ApiKey,
            Err(error) => LoginState::Malformed(error.to_string()),
        },
        LoginFile::OpenAiChatGpt => chatgpt_state(&path),
    }
}

fn chatgpt_state(path: &Path) -> LoginState {
    let store = FileStore::new(path.to_path_buf());
    let stored = match store.read() {
        Ok(stored) => stored,
        Err(error) => return LoginState::Malformed(error.to_string()),
    };
    let state: serde_json::Value = match stored.payload.as_deref().map(serde_json::from_str) {
        Some(Ok(state)) => state,
        Some(Err(error)) => return LoginState::Malformed(error.to_string()),
        None => serde_json::Value::Null,
    };
    let credential = state.get("credential");
    LoginState::ChatGpt {
        account_id: credential
            .and_then(|credential| credential.get("account_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        access_expires_at_ms: credential
            .and_then(|credential| credential.get("expires_at"))
            .and_then(serde_json::Value::as_i64),
        refresh_token: credential
            .and_then(|credential| credential.get("refresh_token"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|token| !token.trim().is_empty()),
        revision: stored.revision,
    }
}

/// The no-spend authenticated read `kata login status --check` makes for each
/// login file: a model LIST (OpenAI's and Anthropic's API keys) or the ChatGPT
/// backend's usage read (the ChatGPT login), each answered `401` to a request
/// carrying no credential (measured 2026-11-03). Only the answer's status is
/// read, never its body. No production config key names another host.
const OPENAI_MODELS_URL: &str = "https://api.openai.com/v1/models";
const ANTHROPIC_MODELS_URL: &str = "https://api.anthropic.com/v1/models";
const CHATGPT_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";

/// Where `kata login status --check` reads: the providers' own hosts and
/// nanocode's issuer, or, under `test-support` only, ONE mock on loopback
/// serving all of them.
#[derive(Clone, Debug, Default)]
pub struct CheckHosts {
    issuer: Issuer,
    /// The loopback mock every read goes to; `None` in production, where
    /// nothing sets it.
    local: Option<std::sync::Arc<str>>,
}

impl CheckHosts {
    /// A mock at `http://127.0.0.1:<port>`: the reads at `/v1/models` and
    /// `/backend-api/wham/usage`, the issuer at its root.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn local_for_test(url: &str) -> Self {
        Self {
            issuer: Issuer::local_for_test(url),
            local: Some(std::sync::Arc::from(url)),
        }
    }

    fn read_url(&self, file: LoginFile) -> String {
        let production = match file {
            LoginFile::OpenAiChatGpt => CHATGPT_USAGE_URL,
            LoginFile::OpenAiApiKey => OPENAI_MODELS_URL,
            LoginFile::AnthropicApiKey => ANTHROPIC_MODELS_URL,
        };
        if let Some(local) = &self.local {
            let path = production
                .split_once("://")
                .and_then(|(_, rest)| rest.find('/').map(|slash| &rest[slash..]))
                .unwrap_or_default();
            return format!("{local}{path}");
        }
        production.to_owned()
    }
}

/// What `kata login status --check` found for one login file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginCheck {
    /// The file does not exist; nothing was contacted.
    Absent,
    /// The provider accepted the credential.
    Ok(String),
    /// The credential is refused: offline (not owner-only, not what kata
    /// wrote, no completed ChatGPT login) or by the provider (`401`/`403`).
    Refused(String),
    /// The ChatGPT access token is past its expiry and its refresh did not
    /// renew it.
    Expired(String),
    /// No answer judged the credential: the provider was unreachable, timed
    /// out, or answered another status.
    Unchecked(String),
}

impl LoginCheck {
    /// The verdict's name.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Ok(_) => "ok",
            Self::Refused(_) => "refused",
            Self::Expired(_) => "expired",
            Self::Unchecked(_) => "unchecked",
        }
    }
}

/// Check `file` in `logins_dir` with ONE authenticated read that spends
/// nothing, against `hosts`:
///
/// * an API key is presented to its provider's model list (OpenAI: the
///   `authorization` bearer; Anthropic: `x-api-key` with nanocode's
///   `anthropic-version`);
/// * the ChatGPT login is opened through nanocode's `ChatGptSubscription`
///   over [`FileStore`], exactly as a turn's load opens it: an access token
///   inside nanocode's refresh window is refreshed first, under the store's
///   lock, and one still past its expiry after that is [`LoginCheck::Expired`]
///   with no read made; otherwise its access token and account are presented
///   to the ChatGPT backend's usage read.
///
/// The provider's `2xx` is [`LoginCheck::Ok`] and its `401` or `403`
/// [`LoginCheck::Refused`]; no answer, or any other status, is
/// [`LoginCheck::Unchecked`] (it judges no credential). A file the offline
/// checks refuse ([`login_state`]'s refusals) is refused with no read made,
/// and an absent file contacts nothing. Nothing is retried.
#[must_use]
pub fn check_login(logins_dir: &Path, file: LoginFile, hosts: &CheckHosts) -> LoginCheck {
    // The offline judgement is `login_state`'s own, so a file `kata login
    // status` refuses (a ChatGPT store that is not nanocode's document
    // included) is refused here before any read, not scored `unchecked`.
    match login_state(logins_dir, file) {
        LoginState::Absent => return LoginCheck::Absent,
        LoginState::Insecure(detail) | LoginState::Malformed(detail) => {
            return LoginCheck::Refused(detail);
        }
        LoginState::ApiKey | LoginState::ChatGpt { .. } => {}
    }
    let path = match check_file(logins_dir, file) {
        Ok(path) => path,
        Err(KataLoginError::Absent { .. }) => return LoginCheck::Absent,
        Err(error) => return LoginCheck::Refused(error.to_string()),
    };
    let url = hosts.read_url(file);
    let checked = match file {
        LoginFile::OpenAiApiKey | LoginFile::AnthropicApiKey => {
            let key = match read_api_key(&path) {
                Ok(key) => key,
                Err(error) => return LoginCheck::Refused(error.to_string()),
            };
            let headers = if file == LoginFile::OpenAiApiKey {
                vec![("authorization", format!("Bearer {key}"))]
            } else {
                vec![
                    ("x-api-key", key),
                    (
                        "anthropic-version",
                        nanocode_backend_claude::ANTHROPIC_VERSION.to_owned(),
                    ),
                ]
            };
            on_own_runtime(async { Ok(authenticated_read(&url, &headers, file).await) })
        }
        LoginFile::OpenAiChatGpt => on_own_runtime(check_chatgpt(path, hosts.issuer.clone(), url)),
    };
    checked.unwrap_or_else(|error| LoginCheck::Unchecked(error.to_string()))
}

async fn check_chatgpt(
    path: PathBuf,
    issuer: Issuer,
    url: String,
) -> Result<LoginCheck, KataLoginError> {
    let judged = |source: ChatGptSubscriptionError| match source {
        ChatGptSubscriptionError::Host(_) | ChatGptSubscriptionError::Contended => {
            LoginCheck::Unchecked(
                KataLoginError::Harness {
                    path: path.clone(),
                    source,
                }
                .to_string(),
            )
        }
        ChatGptSubscriptionError::Invalid(_)
        | ChatGptSubscriptionError::NotAuthenticated
        | ChatGptSubscriptionError::LoginRequired(_) => LoginCheck::Refused(
            KataLoginError::Harness {
                path: path.clone(),
                source,
            }
            .to_string(),
        ),
    };
    let revision = || {
        FileStore::new(path.clone())
            .read()
            .ok()
            .map(|stored| stored.revision)
    };
    let before = revision();
    let subscription = match issuer.open(FileStore::new(path.clone()), None).await {
        Ok(subscription) => subscription,
        Err(source) => return Ok(judged(source)),
    };
    match subscription.status().await {
        Ok(ChatGptLoginStatus::Authenticated { .. }) => {}
        Ok(_) => {
            return Ok(LoginCheck::Refused(
                KataLoginError::NotSignedIn { path }.to_string(),
            ));
        }
        Err(source) => return Ok(judged(source)),
    }
    let credential = match subscription.credential().await {
        Ok(credential) => credential,
        Err(source) => return Ok(judged(source)),
    };
    match subscription.status().await {
        Ok(ChatGptLoginStatus::Authenticated {
            expires_at: Some(expires_at),
            ..
        }) if expires_at <= now_ms() => {
            return Ok(LoginCheck::Expired(
                KataLoginError::Expired { path }.to_string(),
            ));
        }
        Ok(_) => {}
        Err(source) => return Ok(judged(source)),
    }
    let mut headers = vec![
        (
            "authorization",
            format!("Bearer {}", credential.access_token()),
        ),
        ("chatgpt-account-id", credential.account_id().to_owned()),
    ];
    if credential.is_fedramp() {
        headers.push(("x-openai-fedramp", "true".to_owned()));
    }
    let checked = authenticated_read(&url, &headers, LoginFile::OpenAiChatGpt).await;
    let after = revision();
    Ok(match checked {
        LoginCheck::Ok(detail) if after != before => LoginCheck::Ok(format!(
            "{detail}; its access token was refreshed first (store revision {} -> {})",
            before.unwrap_or_default(),
            after.unwrap_or_default()
        )),
        other => other,
    })
}

/// One GET of `url` presenting `headers`, judged by its status alone; the
/// body is never read.
async fn authenticated_read(url: &str, headers: &[(&str, String)], file: LoginFile) -> LoginCheck {
    nanocode_backend_codex::client::transport::install_default_rustls_crypto_provider();
    let client = match reqwest::Client::builder().timeout(ISSUER_TIMEOUT).build() {
        Ok(client) => client,
        Err(error) => return LoginCheck::Unchecked(format!("building the client: {error}")),
    };
    let mut request = client.get(url);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    match request
        .send()
        .await
        .map(|response| response.status().as_u16())
    {
        Ok(status) if (200..300).contains(&status) => {
            LoginCheck::Ok(format!("{url} accepted it (HTTP {status})"))
        }
        Ok(status @ (401 | 403)) => LoginCheck::Refused(format!(
            "{url} refused it (HTTP {status}); run `{}`",
            file.login_command()
        )),
        Ok(status) => LoginCheck::Unchecked(format!(
            "{url} answered HTTP {status}, which judges no credential"
        )),
        Err(error) => LoginCheck::Unchecked(format!(
            "{url} could not be reached: {}",
            error.without_url()
        )),
    }
}

/// What [`logout`] removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// The login files that existed.
    pub files: Vec<LoginFile>,
    /// Temporary copies a crashed write of one of them left behind, and the
    /// staging file of a browser login killed before it removed it.
    pub crashed_copies: Vec<PathBuf>,
}

impl Removed {
    /// Whether nothing was removed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.crashed_copies.is_empty()
    }
}

/// Remove every login file of `provider` from `logins_dir`, and every
/// temporary copy a crashed write of one left ([`sweep_crashed_copies`]),
/// the ChatGPT store's under its lock; for OpenAI, also the browser login's
/// staging file a killed `kata login openai` left (a browser login still
/// running then fails reading it, storing nothing). The issuer is not told:
/// a removed login's tokens stay valid at the issuer until they expire.
///
/// # Errors
/// [`KataLoginError::Io`] for a file that exists and could not be removed.
pub fn logout(logins_dir: &Path, provider: LoginProvider) -> Result<Removed, KataLoginError> {
    let mut removed = Removed::default();
    for file in provider.files() {
        let path = file.path(logins_dir);
        let store = (file == LoginFile::OpenAiChatGpt).then(|| FileStore::new(path.clone()));
        let lock = match &store {
            // Every write of the store took this lock, so a crashed one left
            // it behind: its copy is swept under it, as the store is removed.
            Some(store) if store.lock_path.exists() => Some(on_own_runtime(async {
                store
                    .lock()
                    .await
                    .map_err(|error| KataLoginError::Malformed {
                        path: path.clone(),
                        detail: error.to_string(),
                    })
            })?),
            _ => None,
        };
        match std::fs::remove_file(&path) {
            Ok(()) => removed.files.push(file),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(KataLoginError::Io { path, source }),
        }
        removed
            .crashed_copies
            .extend(sweep_crashed_copies(logins_dir, file)?);
        drop(lock);
    }
    if provider == LoginProvider::Openai {
        let staging = chatgpt_staging(logins_dir);
        match std::fs::remove_file(&staging) {
            Ok(()) => removed.crashed_copies.push(staging.clone()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(KataLoginError::Io {
                    path: staging,
                    source,
                });
            }
        }
        remove_staging(&staging);
    }
    Ok(removed)
}

/// The mock issuer the device-code login cells run against (loopback only).
#[cfg(test)]
#[path = "../tests/fixtures/mock_device_issuer.rs"]
mod mock_device_issuer;

/// The mock provider and issuer the `kata login status --check` cells run
/// against (loopback only).
#[cfg(test)]
#[path = "../tests/fixtures/mock_login_check.rs"]
mod mock_login_check;

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A logins dir created as `kata login` creates it.
    fn logins() -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let dir = logins_dir(home.path());
        ensure_logins_dir(&dir, LoginFile::OpenAiApiKey).unwrap();
        (home, dir)
    }

    /// **The owner-only checks refuse exactly the insecure shapes.** A key
    /// stored by kata loads; the same file group-readable, world-readable, a
    /// symlink to a 0600 file, or hard-linked a second time is refused
    /// `credential_unavailable` naming the path, and so is a group-readable
    /// directory holding a 0600 file. The file's bytes are never needed to
    /// refuse.
    ///
    /// **Would red if:** a check were dropped, or one checked the wrong bits.
    #[test]
    fn a_group_readable_login_file_refuses() {
        let (_home, dir) = logins();
        store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-owner").unwrap();
        let path = LoginFile::OpenAiApiKey.path(&dir);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let loaded = load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::ApiKey,
            &Issuer::default(),
        )
        .unwrap();
        assert_eq!(loaded.scrub, ["sk-owner"]);

        let refused = |dir: &Path| {
            load(
                dir,
                AdapterKind::NanocodeOpenai,
                CredentialMode::ApiKey,
                &Issuer::default(),
            )
            .expect_err("an insecure login must refuse")
        };
        for mode in [0o640, 0o604, 0o620] {
            set_mode(&path, mode);
            let error = refused(&dir);
            assert!(
                matches!(error, KataLoginError::Insecure { .. }),
                "{mode:o}: {error}"
            );
            assert_eq!(error.refusal(), "credential_unavailable");
            assert!(error.to_string().contains("openai-api-key"), "{error}");
        }
        set_mode(&path, 0o600);

        let alias = dir.join("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(refused(&dir).to_string().contains("links"));
        std::fs::remove_file(&alias).unwrap();

        let real = dir.join("real-key");
        std::fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(refused(&dir).to_string().contains("symlink"));
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&real, &path).unwrap();

        set_mode(&dir, 0o750);
        let error = refused(&dir);
        assert!(error.to_string().contains("chmod 700"), "{error}");
        set_mode(&dir, 0o700);
        load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::ApiKey,
            &Issuer::default(),
        )
        .expect("restored to owner-only, the key loads again");
    }

    /// The command after a refusal's `fix: `, run by `/bin/sh` exactly as
    /// printed: the remedy is proven by the shell and the filesystem.
    fn run_printed_fix(refusal: &str) {
        let (_, command) = refusal
            .rsplit_once("fix: ")
            .unwrap_or_else(|| panic!("the refusal prints no fix: {refusal}"));
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .status()
            .unwrap();
        assert!(status.success(), "`{command}` failed: {status}");
    }

    /// **A login store refusal prints the exact `chmod` that fixes it.** The
    /// home here holds a space, so the printed path must be shell-quoted; run
    /// by `sh` as printed, each command is the whole fix and the key loads.
    ///
    /// **Would red if:** a refusal dropped its fix or printed it unquoted.
    #[test]
    fn a_login_store_mode_refusal_prints_the_chmod_that_fixes_it() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("my home");
        let dir = logins_dir(&home);
        ensure_logins_dir(&dir, LoginFile::OpenAiApiKey).unwrap();
        store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-owner").unwrap();
        let path = LoginFile::OpenAiApiKey.path(&dir);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

        set_mode(&dir, 0o750);
        let refusal = check_logins_dir(&dir, LoginFile::OpenAiApiKey)
            .unwrap_err()
            .to_string();
        assert!(
            refusal.ends_with(&format!("fix: chmod 700 '{}'", dir.display())),
            "{refusal}"
        );
        run_printed_fix(&refusal);
        assert_eq!(mode(&dir), 0o700);

        set_mode(&path, 0o640);
        let refusal = check_login_file(&path, LoginFile::OpenAiApiKey)
            .unwrap_err()
            .to_string();
        assert!(
            refusal.ends_with(&format!("fix: chmod 600 '{}'", path.display())),
            "{refusal}"
        );
        run_printed_fix(&refusal);
        assert_eq!(mode(&path), 0o600);
        load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::ApiKey,
            &Issuer::default(),
        )
        .expect("the printed fixes are the whole fix");
    }

    /// **A login path another account owns is refused with the reason, never
    /// a command.** `/usr` and `/etc/passwd` are root's.
    ///
    /// **Would red if:** a refusal dropped its reason or proposed a command.
    #[test]
    fn a_login_path_another_account_owns_is_refused_with_why() {
        use std::os::unix::fs::MetadataExt as _;

        let euid = rustix::process::geteuid().as_raw();
        let usr = std::fs::symlink_metadata("/usr").unwrap();
        let passwd = std::fs::symlink_metadata("/etc/passwd").unwrap();
        assert!(
            usr.is_dir() && usr.uid() != euid,
            "precondition: /usr is another account's directory"
        );
        assert!(
            passwd.is_file() && passwd.nlink() == 1 && passwd.uid() != euid,
            "precondition: /etc/passwd is another account's single-link file"
        );
        let reasons = [
            check_logins_dir(Path::new("/usr"), LoginFile::OpenAiApiKey)
                .unwrap_err()
                .to_string(),
            check_login_file(Path::new("/etc/passwd"), LoginFile::OpenAiApiKey)
                .unwrap_err()
                .to_string(),
        ];
        for refusal in reasons {
            assert!(
                refusal.contains(&format!(
                    "refused: uid 0 owns it, not you (uid {euid}); kata keeps a login only where no other account can read or replace it"
                )),
                "{refusal}"
            );
            assert!(!refusal.contains("fix: "), "{refusal}");
            assert!(!refusal.contains("chown"), "{refusal}");
        }
    }

    /// **A mode reads only its own file.** With only an API key stored,
    /// `subscription` refuses naming `kata login openai` (the ChatGPT store
    /// is absent), and an Anthropic subscription refuses as unavailable in this
    /// build.
    #[test]
    fn a_mode_reads_only_its_own_file() {
        let (_home, dir) = logins();
        store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-owner").unwrap();
        let error = load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            &Issuer::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            KataLoginError::Absent {
                file: LoginFile::OpenAiChatGpt,
                ..
            }
        ));
        assert!(
            error.to_string().contains("run `kata login openai`"),
            "{error}"
        );
        let error = load(
            &dir,
            AdapterKind::NanocodeAnthropic,
            CredentialMode::Subscription,
            &Issuer::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, KataLoginError::ModeUnavailable { .. }),
            "{error}"
        );
    }

    /// **kata stores only a key it can hand back whole.**
    #[test]
    fn an_api_key_with_whitespace_is_not_stored() {
        let (_home, dir) = logins();
        for key in ["", "sk one", "sk-one\n", "sk\tone"] {
            let error = store_api_key(&dir, LoginFile::AnthropicApiKey, key).unwrap_err();
            assert!(
                matches!(error, KataLoginError::KeyRefused { .. }),
                "{key:?}"
            );
            assert!(error.to_string().contains("nothing was written"), "{error}");
        }
        assert!(!LoginFile::AnthropicApiKey.path(&dir).exists());
    }

    /// **The worker's login lookup refuses exactly the kind × mode the CHECK
    /// refuses.** Over every harness kind and both modes,
    /// `LoginProvider::file` names a file exactly when
    /// `AdapterKind::serves_credential_mode` (the CHECK's, the assembly's and
    /// doctor's door) serves the pair: the refused set is spelled twice, and
    /// this ties the spellings.
    ///
    /// **Would red if:** a Claude subscription login were added to one side
    /// and not the other, or either side's refused set moved.
    #[test]
    fn the_login_lookup_refuses_exactly_the_modes_the_check_refuses() {
        let mut harness_kinds = 0;
        for kind in AdapterKind::ALL {
            let provider = LoginProvider::of_kind(kind);
            harness_kinds += 1;
            for mode in [CredentialMode::ApiKey, CredentialMode::Subscription] {
                assert_eq!(
                    provider.file(mode).is_some(),
                    kind.serves_credential_mode(mode),
                    "{kind:?} under {mode:?}"
                );
            }
        }
        assert_eq!(harness_kinds, 2);
    }

    /// **Logout removes the provider's files and only those.**
    #[test]
    fn logout_removes_only_the_providers_files() {
        let (_home, dir) = logins();
        store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-a").unwrap();
        store_api_key(&dir, LoginFile::AnthropicApiKey, "sk-b").unwrap();
        assert_eq!(
            logout(&dir, LoginProvider::Openai).unwrap().files,
            [LoginFile::OpenAiApiKey]
        );
        assert_eq!(
            login_state(&dir, LoginFile::OpenAiApiKey),
            LoginState::Absent
        );
        assert_eq!(
            login_state(&dir, LoginFile::AnthropicApiKey),
            LoginState::ApiKey
        );
        assert!(logout(&dir, LoginProvider::Openai).unwrap().is_empty());
    }

    /// **A crashed write's temporary copy is swept by `kata logout` and by the
    /// next write of its file.** A write that died between creating
    /// `.<file>.<pid>.<ms>.tmp` and renaming it leaves a full owner-only copy of
    /// the credential (for the ChatGPT store, its refresh token) that no
    /// [`LoginFile`] names. Planted beside a stored login, the ChatGPT store's
    /// and the OpenAI key's copies are gone after `logout(openai)`, read off
    /// the directory itself; the Anthropic key's copy and every name outside
    /// the exact `.<file>.<digits>.<digits>.tmp` shape stay. A killed browser
    /// login's staging file `openai-chatgpt.login.json` (and its lock)
    /// survives `logout(anthropic)` and is gone after `logout(openai)`, which
    /// reports it. Planted again, the next ChatGPT store commit and the next
    /// key store each remove their own file's copy and no other.
    ///
    /// **Would red if:** logout removed only the named files (concurrency-48)
    /// or left the staging file's refresh token, a write left an earlier
    /// crash's copy behind, or the sweep matched a name it does not own.
    #[test]
    fn a_crashed_writes_temporary_copy_is_swept_by_logout_and_the_next_write() {
        let (_home, dir) = logins();
        let plant = |name: &str| {
            let path = dir.join(name);
            std::fs::write(&path, "rt-crashed-copy").unwrap();
            set_mode(&path, 0o600);
            path
        };
        let present = |path: &Path| std::fs::symlink_metadata(path).is_ok();
        let seed = |refresh: &str| {
            let token = access_token("acct-owner", now_ms() / 1_000 + 3_600);
            let seed = ChatGptCredentialSeed::new(token, refresh, "acct-owner", false);
            on_own_runtime(store_seed(&dir, seed, &Issuer::default())).unwrap();
        };
        seed("rt-0");
        store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-a").unwrap();
        store_api_key(&dir, LoginFile::AnthropicApiKey, "sk-b").unwrap();

        let chatgpt_copy = plant(".openai-chatgpt.json.4242.1700000000000.tmp");
        let key_copy = plant(".openai-api-key.4243.1700000000001.tmp");
        let anthropic_copy = plant(".anthropic-api-key.4244.1700000000002.tmp");
        let staging = plant("openai-chatgpt.login.json");
        let staging_lock = plant("openai-chatgpt.login.json.lock");
        let foreign = [
            plant(".openai-chatgpt.json.tmp"),
            plant(".openai-chatgpt.json.x.1.tmp"),
            plant("openai-chatgpt.json.4242.1700000000000.tmp"),
            plant(".openai-chatgpt.json.4242.1700000000000.tmp.keep"),
            plant(".openai-chatgpt.json.login.4242.1.tmp"),
        ];
        logout(&dir, LoginProvider::Anthropic).unwrap();
        assert!(!present(&anthropic_copy), "anthropic's own copy survived");
        assert!(
            present(&staging),
            "another provider's logout swept the staging file"
        );
        let anthropic_copy = plant(".anthropic-api-key.4244.1700000000002.tmp");
        let removed = logout(&dir, LoginProvider::Openai).unwrap();
        assert!(
            !present(&staging) && !present(&staging_lock),
            "a killed browser login's staging file survived logout"
        );
        assert!(removed.crashed_copies.contains(&staging), "{removed:?}");
        assert!(
            !present(&chatgpt_copy),
            "the store's crashed copy survived logout"
        );
        assert!(
            !present(&key_copy),
            "the key's crashed copy survived logout"
        );
        assert!(
            present(&anthropic_copy),
            "another provider's copy was swept"
        );
        for path in &foreign {
            assert!(present(path), "{} is not a crash copy", path.display());
        }

        let chatgpt_copy = plant(".openai-chatgpt.json.4242.1700000000003.tmp");
        let key_copy = plant(".openai-api-key.4243.1700000000004.tmp");
        seed("rt-1");
        assert!(
            !present(&chatgpt_copy),
            "the next store commit kept the copy"
        );
        assert!(
            present(&key_copy),
            "a store commit swept another file's copy"
        );
        store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-c").unwrap();
        assert!(!present(&key_copy), "the next key store kept the copy");
        assert!(
            present(&anthropic_copy),
            "a key store swept another file's copy"
        );
        for path in &foreign {
            assert!(present(path), "{} is not a crash copy", path.display());
        }
    }

    /// The login check's fixture: an owner's logins directory, the raw bytes
    /// and the decoded raw state of its ChatGPT store (read off the file, not
    /// through kata), and a seeder.
    mod check {
        use super::super::mock_login_check::{MockLoginCheck, chatgpt_token, now_secs};
        use super::*;

        const ACCOUNT: &str = "acct-owner";
        const ACCEPTED_KEY: &str = "mock-provider-key-1";

        fn seed_chatgpt(dir: &Path, access: &str, refresh: &str) {
            let seed = ChatGptCredentialSeed::new(access, refresh, ACCOUNT, false);
            on_own_runtime(store_seed(dir, seed, &Issuer::default())).unwrap();
        }

        fn store_bytes(dir: &Path) -> Vec<u8> {
            std::fs::read(LoginFile::OpenAiChatGpt.path(dir)).unwrap()
        }

        /// `(revision, access token, refresh token)` as the file holds them.
        fn raw_store(dir: &Path) -> (u64, String, String) {
            let stored: serde_json::Value = serde_json::from_slice(&store_bytes(dir)).unwrap();
            let state: serde_json::Value =
                serde_json::from_str(stored["state"].as_str().unwrap()).unwrap();
            let field = |name: &str| state["credential"][name].as_str().unwrap().to_owned();
            (
                stored["revision"].as_u64().unwrap(),
                field("access_token"),
                field("refresh_token"),
            )
        }

        fn check_all(dir: &Path, hosts: &CheckHosts) -> Vec<LoginCheck> {
            LoginFile::ALL
                .into_iter()
                .map(|file| check_login(dir, file, hosts))
                .collect()
        }

        /// A loopback URL that refuses every connection for as long as it
        /// lives. Its port is held by a socket bound WITHOUT `SO_REUSEADDR`
        /// that never listens: a connect to it is reset, and no other socket
        /// can bind the port while it is held, `SO_REUSEADDR` or
        /// `SO_REUSEPORT` or not, so no parallel cell's mock can come to
        /// answer on it. A port read off a dropped `127.0.0.1:0` listener is
        /// free for the next bind to take.
        struct DeadUrl {
            addr: std::net::SocketAddr,
            url: String,
            _held: tokio::net::TcpSocket,
        }

        impl DeadUrl {
            fn bind() -> Self {
                let held = tokio::net::TcpSocket::new_v4().unwrap();
                held.bind(([127, 0, 0, 1], 0).into()).unwrap();
                let addr = held.local_addr().unwrap();
                Self {
                    addr,
                    url: format!("http://{addr}"),
                    _held: held,
                }
            }
        }

        /// **PASS: each stored login is accepted by its provider, read once,
        /// and nothing is refreshed.** With nothing stored every file is
        /// `absent` and the mock sees no request. Stored, the OpenAI key is
        /// presented as the `authorization` bearer of `GET /v1/models`, the
        /// Anthropic key as `x-api-key` beside `anthropic-version: 2023-06-01`
        /// on the same path, and the fresh ChatGPT login's access token and
        /// account to `GET /backend-api/wham/usage`: three requests, each
        /// `ok`, read off the mock's own record. Nothing is minted and the
        /// store's bytes are unchanged.
        ///
        /// **Would red if:** a credential went out on the wrong header, a
        /// fresh login were refreshed, or an absent file were contacted.
        #[test]
        fn a_stored_login_its_provider_accepts_checks_ok() {
            let (_home, dir) = logins();
            let access = chatgpt_token(ACCOUNT, now_secs() + 3_600, 0);
            let mock =
                MockLoginCheck::start(ACCEPTED_KEY, ACCOUNT, std::slice::from_ref(&access), "rt-0");
            let hosts = CheckHosts::local_for_test(&mock.url);
            assert_eq!(check_all(&dir, &hosts), vec![LoginCheck::Absent; 3]);
            assert!(mock.seen().is_empty(), "{:?}", mock.seen());

            seed_chatgpt(&dir, &access, "rt-0");
            store_api_key(&dir, LoginFile::OpenAiApiKey, ACCEPTED_KEY).unwrap();
            store_api_key(&dir, LoginFile::AnthropicApiKey, ACCEPTED_KEY).unwrap();
            let before = store_bytes(&dir);
            let checks = check_all(&dir, &hosts);
            for check in &checks {
                assert_eq!(check.label(), "ok", "{checks:?}");
            }
            let seen = mock.seen();
            assert_eq!(seen.len(), 3, "{seen:?}");
            let usage = &seen[0];
            assert_eq!(
                (usage.method.as_str(), usage.path.as_str()),
                ("GET", "/backend-api/wham/usage")
            );
            assert_eq!(usage.headers["authorization"], format!("Bearer {access}"));
            assert_eq!(usage.headers["chatgpt-account-id"], ACCOUNT);
            let openai = &seen[1];
            assert_eq!(
                (openai.method.as_str(), openai.path.as_str()),
                ("GET", "/v1/models")
            );
            assert_eq!(
                openai.headers["authorization"],
                format!("Bearer {ACCEPTED_KEY}")
            );
            assert!(!openai.headers.contains_key("x-api-key"), "{openai:?}");
            let anthropic = &seen[2];
            assert_eq!(
                (anthropic.method.as_str(), anthropic.path.as_str()),
                ("GET", "/v1/models")
            );
            assert_eq!(anthropic.headers["x-api-key"], ACCEPTED_KEY);
            assert_eq!(anthropic.headers["anthropic-version"], "2023-06-01");
            assert!(
                !anthropic.headers.contains_key("authorization"),
                "{anthropic:?}"
            );
            assert_eq!(mock.minted(), 0);
            assert_eq!(store_bytes(&dir), before, "a fresh login was rewritten");
        }

        /// **401: a credential its provider refuses checks `refused`, naming
        /// the status and the login command.** Each stored file's single read
        /// is answered `401`, and nothing is refreshed or rewritten.
        ///
        /// **Would red if:** a `401` read as `ok` or `unchecked`, or the check
        /// retried.
        #[test]
        fn a_stored_login_its_provider_answers_401_checks_refused() {
            let (_home, dir) = logins();
            let access = chatgpt_token(ACCOUNT, now_secs() + 3_600, 0);
            let mock = MockLoginCheck::start(ACCEPTED_KEY, ACCOUNT, &[], "rt-0");
            seed_chatgpt(&dir, &access, "rt-0");
            store_api_key(&dir, LoginFile::OpenAiApiKey, "mock-revoked-key-1").unwrap();
            store_api_key(&dir, LoginFile::AnthropicApiKey, "mock-revoked-key-2").unwrap();
            let before = store_bytes(&dir);
            let checks = check_all(&dir, &CheckHosts::local_for_test(&mock.url));
            for (file, check) in LoginFile::ALL.into_iter().zip(&checks) {
                let LoginCheck::Refused(detail) = check else {
                    panic!("{file:?}: {check:?}");
                };
                assert!(detail.contains("HTTP 401"), "{detail}");
                assert!(detail.contains(file.login_command()), "{detail}");
            }
            assert_eq!(mock.seen().len(), 3, "{:?}", mock.seen());
            assert_eq!(mock.minted(), 0);
            assert_eq!(store_bytes(&dir), before);
        }

        /// **EXPIRED, THEN REFRESHED: an expired ChatGPT login is refreshed
        /// under its lock, and the rotated token is what the read presents.**
        /// The file read raw afterwards holds a higher revision, a new
        /// access token and the issuer's rotated refresh token `rt-1`; the
        /// usage read carried exactly that access token; the check is `ok`
        /// and says it refreshed. A second expired login whose refresh token
        /// the issuer refuses checks `expired` and is never read.
        ///
        /// **Would red if:** the check presented the expired token, skipped
        /// the refresh, or read a login its refresh did not renew.
        #[test]
        fn an_expired_chatgpt_login_is_refreshed_then_checked() {
            let (_home, dir) = logins();
            let stale = chatgpt_token(ACCOUNT, now_secs() - 60, 0);
            let mock = MockLoginCheck::start(ACCEPTED_KEY, ACCOUNT, &[], "rt-0");
            let hosts = CheckHosts::local_for_test(&mock.url);
            seed_chatgpt(&dir, &stale, "rt-0");
            let (revision, _, _) = raw_store(&dir);

            let check = check_login(&dir, LoginFile::OpenAiChatGpt, &hosts);
            let LoginCheck::Ok(detail) = &check else {
                panic!("{check:?}");
            };
            assert!(detail.contains("refreshed first"), "{detail}");
            let (refreshed, access, refresh) = raw_store(&dir);
            assert!(refreshed > revision, "{revision} -> {refreshed}");
            assert_ne!(access, stale);
            assert_eq!(refresh, "rt-1");
            assert_eq!(mock.minted(), 1);
            let seen = mock.seen();
            let reads: Vec<_> = seen.iter().filter(|seen| seen.method == "GET").collect();
            assert_eq!(reads.len(), 1, "{seen:?}");
            assert_eq!(
                reads[0].headers["authorization"],
                format!("Bearer {access}")
            );

            let (_other_home, other) = logins();
            seed_chatgpt(&other, &stale, "rt-stale");
            let before = store_bytes(&other);
            let check = check_login(&other, LoginFile::OpenAiChatGpt, &hosts);
            assert_eq!(check.label(), "expired", "{check:?}");
            assert_eq!(
                mock.seen()
                    .iter()
                    .filter(|seen| seen.method == "GET")
                    .count(),
                1,
                "an unrenewed login was read"
            );
            assert_eq!(store_bytes(&other), before);
        }

        /// **UNREACHABLE: a provider that does not answer checks `unchecked`,
        /// never `ok` or `refused`.** Against a loopback port held bound and
        /// never listening for the whole cell (read off the kernel: a second
        /// bind of it is refused), both keys and a fresh ChatGPT login are
        /// `unchecked` naming the read, and the store is unchanged; an EXPIRED
        /// ChatGPT login whose issuer is unreachable is `expired` (its refresh
        /// did not renew it).
        ///
        /// **Would red if:** a transport failure were scored as a verdict on
        /// the credential, or the dead port were released for a parallel
        /// cell's mock to bind and answer.
        #[test]
        fn an_unreachable_provider_checks_unchecked() {
            let (_home, dir) = logins();
            let dead = DeadUrl::bind();
            let rebind = std::net::TcpListener::bind(dead.addr).map(drop);
            assert_eq!(
                rebind.map_err(|error| error.kind()),
                Err(std::io::ErrorKind::AddrInUse),
                "another socket could bind the dead port {}",
                dead.addr
            );
            let hosts = CheckHosts::local_for_test(&dead.url);
            seed_chatgpt(&dir, &chatgpt_token(ACCOUNT, now_secs() + 3_600, 0), "rt-0");
            store_api_key(&dir, LoginFile::OpenAiApiKey, ACCEPTED_KEY).unwrap();
            store_api_key(&dir, LoginFile::AnthropicApiKey, ACCEPTED_KEY).unwrap();
            let before = store_bytes(&dir);
            for check in check_all(&dir, &hosts) {
                let LoginCheck::Unchecked(detail) = &check else {
                    panic!("{check:?}");
                };
                assert!(detail.contains("could not be reached"), "{detail}");
            }
            assert_eq!(store_bytes(&dir), before);

            let (_other_home, other) = logins();
            seed_chatgpt(&other, &chatgpt_token(ACCOUNT, now_secs() - 60, 0), "rt-0");
            let check = check_login(&other, LoginFile::OpenAiChatGpt, &hosts);
            assert_eq!(check.label(), "expired", "{check:?}");
        }

        /// **OFFLINE REFUSED: a login the offline checks refuse, or a store
        /// holding no completed ChatGPT login, checks `refused` with no read
        /// made.** Against a mock that would accept every credential: both
        /// keys and the store group/world-readable (0644), a store that is
        /// not nanocode's document, and a store whose login was signed out
        /// through nanocode itself are each `refused`, and the mock records no
        /// request at all.
        ///
        /// **Would red if:** an insecure or malformed file, or a signed-out
        /// store, were presented to a provider, or scored as anything but
        /// `refused`.
        #[test]
        fn an_offline_refused_login_checks_refused_with_no_read() {
            let access = chatgpt_token(ACCOUNT, now_secs() + 3_600, 0);
            let mock =
                MockLoginCheck::start(ACCEPTED_KEY, ACCOUNT, std::slice::from_ref(&access), "rt-0");
            let hosts = CheckHosts::local_for_test(&mock.url);
            let refused = |dir: &Path, file: LoginFile| {
                let check = check_login(dir, file, &hosts);
                assert_eq!(check.label(), "refused", "{file:?}: {check:?}");
            };

            let (_home, dir) = logins();
            seed_chatgpt(&dir, &access, "rt-0");
            store_api_key(&dir, LoginFile::OpenAiApiKey, ACCEPTED_KEY).unwrap();
            store_api_key(&dir, LoginFile::AnthropicApiKey, ACCEPTED_KEY).unwrap();
            for file in LoginFile::ALL {
                set_mode(&file.path(&dir), 0o644);
                refused(&dir, file);
            }

            let (_malformed_home, malformed) = logins();
            let path = LoginFile::OpenAiChatGpt.path(&malformed);
            std::fs::write(&path, "not a nanocode store").unwrap();
            set_mode(&path, 0o600);
            refused(&malformed, LoginFile::OpenAiChatGpt);

            let (_signed_out_home, signed_out) = logins();
            seed_chatgpt(&signed_out, &access, "rt-0");
            let path = LoginFile::OpenAiChatGpt.path(&signed_out);
            on_own_runtime(async {
                Issuer::default()
                    .open(FileStore::new(path.clone()), None)
                    .await
                    .unwrap()
                    .logout()
                    .await
                    .unwrap();
                Ok::<(), KataLoginError>(())
            })
            .unwrap();
            assert!(path.exists(), "a signed-out store is still a file");
            refused(&signed_out, LoginFile::OpenAiChatGpt);

            assert!(mock.seen().is_empty(), "{:?}", mock.seen());
            assert_eq!(mock.minted(), 0);
        }
    }

    /// An unsigned JWT over `claims` (nanocode reads only the payload).
    fn jwt(claims: &serde_json::Value) -> String {
        use base64::Engine as _;
        let encode = |value: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        format!(
            "{}.{}.sig",
            encode(&serde_json::json!({"alg": "none"})),
            encode(claims)
        )
    }

    fn access_token(account: &str, exp_secs: i64) -> String {
        jwt(&serde_json::json!({
            "exp": exp_secs,
            "https://api.openai.com/auth": {"chatgpt_account_id": account},
        }))
    }

    /// **The offline status reads the state nanocode itself wrote, and a fresh
    /// login loads with no issuer round trip.** A login seeded through
    /// nanocode's own `ChatGptSubscription` (the store `kata login openai`
    /// fills) reads back as signed in to its account with its access token's
    /// expiry, a refresh token and two committed revisions (the clear, then
    /// the seed); and loading it, an hour from expiry, hands out exactly that
    /// access token as the bearer. The default issuer is never contacted:
    /// nothing is inside the refresh window.
    ///
    /// **Would red if:** nanocode renamed the state fields the status (and the
    /// refresh's supersede check) reads, or the load refreshed a fresh token.
    #[test]
    fn the_offline_status_reads_the_state_nanocode_wrote() {
        let (_home, dir) = logins();
        let exp = now_ms() / 1_000 + 3_600;
        let token = access_token("acct-owner", exp);
        let seed = ChatGptCredentialSeed::new(token.clone(), "rt-0", "acct-owner", false);
        let account = on_own_runtime(store_seed(&dir, seed, &Issuer::default())).unwrap();
        assert_eq!(account.account_id, "acct-owner");
        assert_eq!(
            login_state(&dir, LoginFile::OpenAiChatGpt),
            LoginState::ChatGpt {
                account_id: Some("acct-owner".into()),
                access_expires_at_ms: Some(exp * 1_000),
                refresh_token: true,
                revision: 2,
            }
        );
        let path = LoginFile::OpenAiChatGpt.path(&dir);
        assert_eq!(
            FileStore::new(path.clone())
                .stored_refresh_token()
                .unwrap()
                .as_deref(),
            Some("rt-0")
        );
        check_login_file(&path, LoginFile::OpenAiChatGpt).unwrap();
        let loaded = load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            &Issuer::default(),
        )
        .unwrap();
        assert_eq!(loaded.scrub, std::slice::from_ref(&token));
        let HarnessAuth::OpenAi(auth) = loaded.auth else {
            panic!("the OpenAI arm");
        };
        let snapshot = on_own_runtime(async move {
            auth.snapshot()
                .await
                .map_err(|error| KataLoginError::Malformed {
                    path: PathBuf::new(),
                    detail: error.to_string(),
                })
        })
        .unwrap();
        assert_eq!(snapshot.bearer(), token);
        assert_eq!(snapshot.account_id(), Some("acct-owner"));
    }

    /// **A completed browser login's document seeds kata's store.** The
    /// staging file `ChatGptLogin` writes (the codex `auth.json` shape, here
    /// written by hand) yields a seed carrying its access and refresh tokens
    /// and the id token's account, and the store holds exactly those.
    #[test]
    fn a_browser_login_document_seeds_the_store() {
        let (_home, dir) = logins();
        let staging = dir.join("openai-chatgpt.login.json");
        let token = access_token("acct-owner", now_ms() / 1_000 + 3_600);
        let document = serde_json::json!({
            "auth_mode": "chatgpt",
            "tokens": {
                "id_token": jwt(&serde_json::json!({
                    "https://api.openai.com/auth": {"chatgpt_account_id": "acct-owner"},
                })),
                "access_token": token,
                "refresh_token": "rt-login",
                "account_id": "acct-owner",
            },
        });
        write_owner_only(&staging, document.to_string().as_bytes()).unwrap();
        let seed = seed_from_codex_document(&staging).unwrap();
        on_own_runtime(store_seed(&dir, seed, &Issuer::default())).unwrap();
        remove_staging(&staging);
        assert!(!staging.exists());
        let path = LoginFile::OpenAiChatGpt.path(&dir);
        assert_eq!(
            FileStore::new(path)
                .stored_refresh_token()
                .unwrap()
                .as_deref(),
            Some("rt-login")
        );
        assert!(matches!(
            login_state(&dir, LoginFile::OpenAiChatGpt),
            LoginState::ChatGpt { account_id: Some(account), refresh_token: true, .. }
                if account == "acct-owner"
        ));
    }

    /// **A holder that keeps the lock past the wait is refused AT the wait, not
    /// when it lets go.** The test holds `openai-chatgpt.json.lock` itself (an
    /// open file description of its own, as another process would) for 6 s;
    /// a store whose wait is 500 ms asks for the lock through the same
    /// [`on_own_runtime`] every caller uses. The call returns, refused naming
    /// the wait, well before the holder releases: the clock, not kata, says
    /// when.
    ///
    /// **Would red if:** the own runtime's teardown waited for the blocking
    /// `flock` thread still parked on the holder's lock (the call would return
    /// only at the holder's release, ~6 s).
    #[test]
    fn a_lock_held_past_the_wait_refuses_at_the_wait() {
        use std::os::unix::fs::OpenOptionsExt as _;

        let (_home, dir) = logins();
        let mut store = FileStore::new(LoginFile::OpenAiChatGpt.path(&dir));
        store.lock_wait = Duration::from_millis(500);
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&store.lock_path)
            .unwrap();
        holder.lock().unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(6));
            drop(holder);
        });
        let started = std::time::Instant::now();
        let refused = on_own_runtime(async {
            store
                .lock()
                .await
                .map(drop)
                .map_err(|error| KataLoginError::Malformed {
                    path: PathBuf::new(),
                    detail: error.to_string(),
                })
        })
        .unwrap_err();
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(3),
            "refused after {waited:?}, not at the 500 ms wait: {refused}"
        );
        assert!(
            refused
                .to_string()
                .contains("kept the login's lock past 500ms"),
            "{refused}"
        );
        release.join().unwrap();
    }

    /// An issuer URL nothing listens on: a refresh against it fails as a
    /// transport error, the transient failure nanocode logs and survives.
    ///
    /// Port 1 is below `net.ipv4.ip_unprivileged_port_start` (1024 by default),
    /// so no unprivileged process — no other cell's mock in a parallel run —
    /// can bind it and answer the refresh. A port read off a dropped
    /// `127.0.0.1:0` listener is free for the next bind to take.
    fn unreachable_issuer() -> Issuer {
        Issuer::local_for_test("http://127.0.0.1:1")
    }

    /// **A failed refresh refuses only a token that is already expired.** A
    /// ChatGPT login whose access token has 2 minutes left (inside nanocode's
    /// early-refresh window) and whose issuer is unreachable still loads, with
    /// that token as the bearer: nanocode refreshes again mid-turn. The same
    /// login with a token that expired a minute ago refuses
    /// `credential_expired`.
    ///
    /// **Would red if:** the load refused a still-valid token inside a refresh
    /// window of kata's own (a copy of nanocode's private constant that a
    /// nanocode bump could leave wider than nanocode's), or loaded a dead one.
    #[test]
    fn a_failed_refresh_refuses_only_an_expired_token() {
        let issuer = unreachable_issuer();
        let (_home, dir) = logins();
        let live = access_token("acct-owner", now_ms() / 1_000 + 120);
        let seed = ChatGptCredentialSeed::new(live.clone(), "rt-0", "acct-owner", false);
        on_own_runtime(store_seed(&dir, seed, &issuer)).unwrap();
        let loaded = load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            &issuer,
        )
        .expect("a token with 2 minutes left loads");
        assert_eq!(loaded.scrub, std::slice::from_ref(&live));

        let (_home, dir) = logins();
        let dead = access_token("acct-owner", now_ms() / 1_000 - 60);
        let seed = ChatGptCredentialSeed::new(dead, "rt-0", "acct-owner", false);
        on_own_runtime(store_seed(&dir, seed, &issuer)).unwrap();
        let error = load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            &issuer,
        )
        .unwrap_err();
        assert_eq!(error.refusal(), "credential_expired", "{error}");
    }

    /// **The store's compare-and-swap refuses a stale revision.** The first
    /// commit from revision 0 lands as revision 1 in a 0600 file; a second
    /// commit expecting 0 is a conflict naming 1, and the file is unchanged.
    #[test]
    fn the_store_refuses_a_stale_revision() {
        let (_home, dir) = logins();
        let path = LoginFile::OpenAiChatGpt.path(&dir);
        let store = FileStore::new(path.clone());
        on_own_runtime(async {
            let first = store
                .compare_and_swap(CHATGPT_KEY, 0, "{\"a\":1}")
                .await
                .map_err(|error| KataLoginError::Malformed {
                    path: path.clone(),
                    detail: error.to_string(),
                })?;
            assert_eq!(first, SubscriptionCommit::Committed(1));
            let second = store
                .compare_and_swap(CHATGPT_KEY, 0, "{\"a\":2}")
                .await
                .map_err(|error| KataLoginError::Malformed {
                    path: path.clone(),
                    detail: error.to_string(),
                })?;
            assert_eq!(second, SubscriptionCommit::Conflict(1));
            Ok(())
        })
        .unwrap();
        let stored: StoredState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!((stored.revision, stored.state.as_str()), (1, "{\"a\":1}"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        check_login_file(&path, LoginFile::OpenAiChatGpt).unwrap();
    }

    /// The names in `dir`, sorted; an absent directory has none.
    fn names(dir: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Store a browser-shaped login (the seed `kata login openai`'s browser
    /// half yields) in `dir`, contacting no issuer.
    fn seed_login(dir: &Path, access: &str, refresh: &str, account: &str) {
        ensure_logins_dir(dir, LoginFile::OpenAiChatGpt).unwrap();
        let seed = ChatGptCredentialSeed::new(access, refresh, account, false);
        on_own_runtime(store_seed(dir, seed, &Issuer::default())).unwrap();
    }

    /// Run the device login against `issuer` on `store` until it answers or
    /// `interrupted` does; also the code it handed the operator.
    fn device_login(
        dir: &Path,
        issuer: &mock_device_issuer::MockDeviceIssuer,
        store: DeviceStore,
        interrupted: impl std::future::Future<Output = ()> + Send,
    ) -> (Result<ChatGptAccount, KataLoginError>, Option<DeviceCode>) {
        let shown = Mutex::new(None);
        let local = Issuer::local_for_test(&issuer.url);
        let answer = on_own_runtime(login_device_code_on(
            store,
            dir,
            &local,
            |code| *shown.lock().unwrap() = Some(code.clone()),
            interrupted,
        ));
        (answer, shown.into_inner().unwrap())
    }

    /// **A device-code login stores the very login the browser login stores.**
    /// Against a mock issuer that answers codex 0.165.0's device endpoints
    /// (`mock_device_issuer`: a string `interval` of 1 s, two `403` polls,
    /// then the approval, exchanged on the form codex sends), the login hands
    /// the operator the issuer's `/codex/device` page and its user code, polls
    /// three times no faster than the stated interval, exchanges once, and
    /// stores `openai-chatgpt.json`. Read back through the store's own readers
    /// it is a ChatGPT login for the issuer's account with a refresh token,
    /// and it loads with the minted access token as the bearer; read with
    /// `std::fs` it is a regular 0600 single-link file of this uid in a 0700
    /// directory, next to nothing but its lock; and it is equal, revision and
    /// state, to the file the browser login's [`store_seed`] writes from the
    /// same tokens.
    ///
    /// **Would red if:** the device flow polled faster than the issuer's
    /// interval, sent a request codex's issuer would not accept, stored a
    /// different file kind, or left its pending state on disk.
    #[test]
    fn a_device_login_stores_the_login_the_browser_login_stores() {
        use mock_device_issuer as mock;
        use std::os::unix::fs::MetadataExt as _;

        let issuer = mock::MockDeviceIssuer::start(mock::Script {
            pending_polls: 2,
            ..mock::Script::default()
        });
        let home = tempfile::tempdir().unwrap();
        let dir = logins_dir(home.path());
        let (answer, shown) = device_login(
            &dir,
            &issuer,
            DeviceStore::default(),
            std::future::pending(),
        );
        let account = answer.expect("the approved device login");
        assert_eq!(account.account_id, mock::ACCOUNT);
        let shown = shown.expect("the operator was shown the code");
        assert_eq!(
            (shown.verification_url.as_str(), shown.user_code.as_str()),
            (
                format!("{}/codex/device", issuer.url).as_str(),
                mock::USER_CODE
            )
        );
        assert!(shown.expires_at_ms > now_ms(), "{shown:?}");

        assert_eq!((issuer.usercodes(), issuer.exchanges()), (1, 1));
        let polls = issuer.polls();
        assert_eq!(polls.len(), 3, "two pending polls, then the approval");
        for pair in polls.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                gap >= Duration::from_millis(900),
                "polled {gap:?} after the last poll; the issuer's interval is 1 s"
            );
        }

        let path = LoginFile::OpenAiChatGpt.path(&dir);
        check_login_file(&path, LoginFile::OpenAiChatGpt).expect("the store's own check");
        let minted = issuer.minted_access().unwrap();
        match login_state(&dir, LoginFile::OpenAiChatGpt) {
            LoginState::ChatGpt {
                account_id,
                refresh_token,
                revision,
                ..
            } => assert_eq!(
                (account_id.as_deref(), refresh_token, revision),
                (Some(mock::ACCOUNT), true, 2)
            ),
            other => panic!("not a ChatGPT login: {other:?}"),
        }
        let loaded = load(
            &dir,
            AdapterKind::NanocodeOpenai,
            CredentialMode::Subscription,
            &Issuer::local_for_test(&issuer.url),
        )
        .expect("the stored login loads");
        assert_eq!(loaded.scrub, std::slice::from_ref(&minted));

        let file = std::fs::symlink_metadata(&path).unwrap();
        assert!(file.file_type().is_file());
        assert_eq!(
            (file.mode() & 0o777, file.uid(), file.nlink()),
            (0o600, rustix::process::geteuid().as_raw(), 1)
        );
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            names(&dir),
            ["openai-chatgpt.json", "openai-chatgpt.json.lock"]
        );

        let browser_home = tempfile::tempdir().unwrap();
        let browser = logins_dir(browser_home.path());
        seed_login(&browser, &minted, mock::MINTED_REFRESH, mock::ACCOUNT);
        let read = |dir: &Path| -> (u64, serde_json::Value) {
            let stored: StoredState =
                serde_json::from_slice(&std::fs::read(LoginFile::OpenAiChatGpt.path(dir)).unwrap())
                    .unwrap();
            (
                stored.revision,
                serde_json::from_str(&stored.state).unwrap(),
            )
        };
        assert_eq!(read(&dir), read(&browser), "one file kind for both flows");
    }

    /// **A device login the issuer refuses stores nothing, by name.** A code
    /// request answered `404` refuses `device_code_not_enabled`, quoting
    /// codex's own message and naming `kata login openai --browser`; a poll
    /// answered `401` after one pending poll refuses `device_code_refused`
    /// naming the status and the step. Each writes no file into a fresh logins
    /// directory, and leaves an earlier login's directory byte-for-byte as it
    /// was.
    ///
    /// **Would red if:** the device flow ran on kata's own store (nanocode's
    /// `start_login` clears it), or a refusal were reported by nanocode's
    /// prose instead of the issuer's status.
    #[test]
    fn a_refused_device_login_stores_nothing_and_keeps_the_earlier_login() {
        use mock_device_issuer as mock;

        let cases = [
            (
                mock::Script {
                    usercode_status: 404,
                    ..mock::Script::default()
                },
                [
                    "device_code_not_enabled",
                    "\"device code login is not enabled for this Codex server. Use the browser \
                     login or verify the server URL.\"",
                    "`kata login openai --browser`",
                ],
            ),
            (
                mock::Script {
                    pending_polls: 1,
                    poll_refusal: Some(401),
                    ..mock::Script::default()
                },
                [
                    "device_code_refused",
                    "HTTP 401 to the approval poll",
                    "nothing was stored",
                ],
            ),
        ];
        for (script, expected) in cases {
            let issuer = mock::MockDeviceIssuer::start(script.clone());
            let fresh_home = tempfile::tempdir().unwrap();
            let fresh = logins_dir(fresh_home.path());
            let (answer, _) = device_login(
                &fresh,
                &issuer,
                DeviceStore::default(),
                std::future::pending(),
            );
            let error = answer.expect_err("the issuer refused").to_string();
            for needle in expected {
                assert!(error.contains(needle), "{script:?}: {error}");
            }
            assert!(names(&fresh).is_empty(), "{script:?}: {:?}", names(&fresh));
            assert_eq!(issuer.exchanges(), 0);

            let issuer = mock::MockDeviceIssuer::start(script.clone());
            let earlier_home = tempfile::tempdir().unwrap();
            let earlier = logins_dir(earlier_home.path());
            seed_login(
                &earlier,
                &access_token("acct-earlier", now_ms() / 1_000 + 3_600),
                "rt-0",
                "acct-earlier",
            );
            let path = LoginFile::OpenAiChatGpt.path(&earlier);
            let before = (names(&earlier), std::fs::read(&path).unwrap());
            let (answer, _) = device_login(
                &earlier,
                &issuer,
                DeviceStore::default(),
                std::future::pending(),
            );
            assert!(answer.is_err(), "{script:?}");
            assert_eq!(
                (names(&earlier), std::fs::read(&path).unwrap()),
                before,
                "{script:?}"
            );
        }
    }

    /// **A pending poll answered `404` keeps the login polling.** codex and
    /// nanocode read a poll's `404` as "not approved yet", exactly as they
    /// read `403`; a login whose pending polls are answered `404` keeps
    /// polling, and when a later poll is refused (`401`) the refusal names
    /// THAT status, never the pending `404`s before it. It writes no file.
    ///
    /// **Would red if:** a poll's `404` were recorded as a refusal: the login
    /// would then be reported `device_code_refused` with HTTP 404, the status
    /// of a poll that only meant "keep waiting".
    #[test]
    fn a_pending_poll_answered_404_keeps_polling_and_a_later_refusal_names_its_own_status() {
        use mock_device_issuer as mock;

        let script = mock::Script {
            pending_polls: 2,
            pending_status: 404,
            poll_refusal: Some(401),
            ..mock::Script::default()
        };
        let issuer = mock::MockDeviceIssuer::start(script.clone());
        let home = tempfile::tempdir().unwrap();
        let dir = logins_dir(home.path());
        let (answer, shown) = device_login(
            &dir,
            &issuer,
            DeviceStore::default(),
            std::future::pending(),
        );
        assert!(shown.is_some(), "the code was shown before the polls");
        let error = answer.expect_err("the third poll is refused").to_string();
        assert!(error.contains("device_code_refused"), "{error}");
        assert!(error.contains("HTTP 401 to the approval poll"), "{error}");
        assert!(!error.contains("HTTP 404"), "{error}");
        assert_eq!(
            issuer.polls().len(),
            3,
            "both 404s were read as pending and polled past: {script:?}"
        );
        assert!(names(&dir).is_empty(), "{:?}", names(&dir));
        assert_eq!(issuer.exchanges(), 0);
    }

    /// **A device code that expires stores nothing.** A login whose code the
    /// issuer never approves is aged past its expiry after the first poll (the
    /// pending state's `expires_at`, in the store the login runs on); the
    /// login refuses `device_code_expired` and writes no file.
    ///
    /// The ageing reaches into nanocode's persisted pending state
    /// (`pending.expires_at` at the pinned rev), so this pins kata's mapping
    /// of nanocode's `Expired` status, not an issuer's answer at expiry: codex
    /// and nanocode both hold the 15-minute TTL on the client. A nanocode bump
    /// that renames the field fails the precondition below by name instead of
    /// leaving the login polling.
    ///
    /// **Would red if:** an expired code kept the login polling, or was
    /// reported as anything but expired.
    #[test]
    fn an_expired_device_code_stores_nothing() {
        use mock_device_issuer as mock;

        let issuer = mock::MockDeviceIssuer::start(mock::Script {
            pending_polls: usize::MAX,
            ..mock::Script::default()
        });
        let home = tempfile::tempdir().unwrap();
        let dir = logins_dir(home.path());
        let store = DeviceStore::default();
        // The state the cell found when it had nothing to age; the login is then
        // interrupted rather than left polling a code that never expires.
        let unaged: std::sync::Arc<Mutex<Option<serde_json::Value>>> = std::sync::Arc::default();
        let (answer, _) = std::thread::scope(|scope| {
            let (aged, found) = (store.clone(), std::sync::Arc::clone(&unaged));
            let issuer = &issuer;
            scope.spawn(move || {
                while issuer.polls().is_empty() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let mut value = aged.value.lock().unwrap();
                let mut state: serde_json::Value =
                    serde_json::from_str(value.payload.as_deref().unwrap()).unwrap();
                if !state["pending"]["expires_at"].is_i64() {
                    *found.lock().unwrap() = Some(state);
                    return;
                }
                state["pending"]["expires_at"] = serde_json::json!(1);
                value.payload = Some(state.to_string());
                value.revision += 1;
            });
            let found = std::sync::Arc::clone(&unaged);
            let gave_up = async move {
                while found.lock().unwrap().is_none() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            device_login(&dir, issuer, store.clone(), gave_up)
        });
        if let Some(state) = unaged.lock().unwrap().take() {
            panic!(
                "nanocode's pending device state keeps its expiry at `pending.expires_at`, \
                 which this cell ages: {state}"
            );
        }
        let error = answer.expect_err("the code expired").to_string();
        assert!(error.contains("device_code_expired"), "{error}");
        assert!(error.contains("nothing was stored"), "{error}");
        assert!(names(&dir).is_empty(), "{:?}", names(&dir));
        assert_eq!(issuer.exchanges(), 0);
    }

    /// **An interrupted device login stores nothing.** A login whose code is
    /// never approved, interrupted after its first poll (the future the CLI
    /// fills with Ctrl-C), refuses `device_code_interrupted`; it writes no file
    /// into a fresh logins directory and leaves an earlier login byte-for-byte
    /// as it was.
    ///
    /// **Would red if:** the pending login were written to disk before the
    /// approval, or the interrupt were not honoured during the wait.
    #[test]
    fn an_interrupted_device_login_stores_nothing() {
        use mock_device_issuer as mock;

        for earlier in [false, true] {
            let issuer = mock::MockDeviceIssuer::start(mock::Script {
                pending_polls: usize::MAX,
                ..mock::Script::default()
            });
            let home = tempfile::tempdir().unwrap();
            let dir = logins_dir(home.path());
            if earlier {
                seed_login(
                    &dir,
                    &access_token("acct-earlier", now_ms() / 1_000 + 3_600),
                    "rt-0",
                    "acct-earlier",
                );
            }
            let path = LoginFile::OpenAiChatGpt.path(&dir);
            let before = (names(&dir), std::fs::read(&path).ok());
            let first_poll = async {
                while issuer.polls().is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            let (answer, shown) = device_login(&dir, &issuer, DeviceStore::default(), first_poll);
            assert!(shown.is_some());
            let error = answer.expect_err("interrupted").to_string();
            assert!(error.contains("device_code_interrupted"), "{error}");
            let after = (names(&dir), std::fs::read(&path).ok());
            if earlier {
                assert_eq!(after, before);
            } else {
                assert_eq!(after, (Vec::new(), None));
            }
        }
    }
}
