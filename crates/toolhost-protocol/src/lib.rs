//! The wire between a kata worker and `kata-toolhost`, the init of an agent
//! capsule.
//!
//! A rootless runtime cannot exec a second process into a running container, so
//! the agent harness runs in the worker and every tool call it makes (a shell
//! command, its stdin, a file read, write or removal) travels to the capsule's
//! init as a [`WorkerFrame`] over the capsule's stdin. The toolhost answers with
//! [`ToolhostFrame`]s on its stdout; its stderr carries plain-text diagnostics,
//! never frames.
//!
//! # The frame
//!
//! The provider protocol's, reused rather than restated:
//! `[u32 big-endian body length][UTF-8 JSON body]`. The codec items re-exported
//! below ARE `kata_provider_protocol`'s, so the two wires share one length rule
//! and one 8 MiB ceiling. This protocol's number, [`TOOLHOST_PROTOCOL_VERSION`],
//! moves independently of the provider protocol's numbers and of the worker's
//! attempt protocol.
//!
//! # What a read refuses
//!
//! Exactly this set, each as a [`FrameError`]:
//!
//! * a declared length of zero, or above [`MAX_FRAME_BYTES`] (also refused on
//!   write, so this build cannot emit a frame it would refuse to read);
//! * a body that is not JSON;
//! * a `kind` this version does not define. `list`, `stat`, `glob` and `search`
//!   are absent on purpose: no caller uses them, and listing and searching happen
//!   through `exec` inside the capsule;
//! * a field this version does not define, on the envelope or in a frame;
//! * an absent field, `Option` fields included: `None` is sent as `null`, so an
//!   absent key is never read as a decision nobody made;
//! * a [`Chunk`] that is not canonical base64 or carries more than
//!   [`MAX_CHUNK_BYTES`];
//! * a [`FileBody`] that is not canonical base64 or carries more than
//!   [`MAX_FILE_BYTES`], the second refused as `toolhost_file_too_large`
//!   ([`FileTooLarge`]).
//!
//! Every frame is a struct variant or a plain struct, so a consumer that binds
//! frames by an exhaustive destructure (no `..`) fails to compile when a field
//! is added.
//!
//! # Identity
//!
//! The toolhost's first frame is an unsolicited [`Hello`] stating
//! [`TOOLHOST_PROTOCOL_VERSION`] and [`TOOLHOST_SOURCE_DIGEST`]; the worker reads
//! no other frame before it and refuses with [`ToolhostMismatch`] unless
//! [`Hello::check`] passes. `Hello` is a self-report: it catches an honest build
//! mismatch (a stale binary from an older checkout), not a binary that lies about
//! itself. Its shape never changes across protocol versions, so a toolhost of any
//! version is refused by its number rather than as a malformed frame.
//!
//! # Sessions
//!
//! A [`WorkerFrame::Exec`] starts a session: one process in a process group of
//! its own, numbered by the worker. Its output streams as
//! [`ToolhostFrame::Output`] while it runs, and its end is one
//! [`ToolhostFrame::Exited`]. Nothing ties a session's life to the request that
//! started it, so a process a tool call leaves running (codex's `exec_command`
//! past its yield, claude's `Bash` with `run_in_background`) is polled later in
//! the same turn by reading what the worker gathered from its `Output` frames,
//! written to with [`WorkerFrame::Stdin`], and stopped with
//! [`WorkerFrame::Signal`]. A `Stdin` or `Signal` naming a session that is not
//! live is answered [`ToolhostFrame::SessionGone`].
//!
//! [`WorkerFrame::KillAll`] ends every DESCENDANT of the toolhost, not only
//! each session's process group. The toolhost is a child subreaper (in a
//! capsule, its pid namespace's init), so a process that left its session's
//! group (`setsid`, a daemonizing double fork) is re-parented below it rather
//! than lost. Each pass walks `/proc` for every process whose parent chain
//! reaches the toolhost and sends each a SIGKILL through a pidfd opened on it,
//! only while that process still has the start time the walk read, so a
//! recycled pid is never signalled; then it reaps. The passes repeat until
//! `/proc` lists no descendant and every session that was live has written its
//! `Exited`, and only then is [`ToolhostFrame::Done`] answered. So once that
//! `Done` is read, no process the toolhost started is alive and no frame of an
//! earlier session follows it. [`WorkerFrame::Shutdown`] does the same before
//! its `Bye`.
//!
//! The passes back off and stop at a deadline of a few seconds, under the
//! worker's wait for the answer. A kill that reaches it with a descendant
//! still listed (a zombie its tracer never waited on, a process in an
//! uninterruptible sleep), or with a session's `Exited` it could not queue
//! because the worker stopped reading, is answered [`ToolhostFrame::Error`]
//! with the request's id, naming what stayed, never `Done` or `Bye`. That
//! `Error` is the last frame the toolhost writes, if it can write it within a
//! second; the toolhost then exits, which, as the capsule's pid-namespace init,
//! makes the kernel kill every process left in the capsule.
//!
//! # Files
//!
//! File contents travel as bytes: base64 on the wire, one [`FileBody`] of at
//! most [`MAX_FILE_BYTES`] raw per frame. [`WorkerFrame::ReadFile`] is answered
//! [`ToolhostFrame::FileBytes`], and [`WorkerFrame::WriteFile`] carries its body.
//! Whether the bytes are text is the worker's question (nanocode's
//! `FileHost::read` wants UTF-8; `read_bytes`, which reads an image, does not),
//! so the toolhost never judges an encoding. Base64 rather than a JSON string,
//! because its size does not depend on the bytes: a body at the cap is the same
//! number of characters whatever it holds, so a frame carrying one fits
//! [`MAX_FRAME_BYTES`], where the escapes of a JSON string could inflate a
//! capped file several times over. The toolhost answers a file over the cap with
//! a `FileError` (EFBIG) and never reads past it; a body over the cap is refused
//! by the codec on either side.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use kata_provider_protocol::{
    FRAME_HEADER_BYTES, FrameError, MAX_FRAME_BYTES, body_len, decode_frame, encode_frame,
    read_frame, write_frame,
};

/// The toolhost protocol number: frame shapes and their meaning.
pub const TOOLHOST_PROTOCOL_VERSION: u32 = 2;

/// The blake3 hex digest of the toolhost's source as this build compiled it
/// (`build.rs` names the files it covers and the encoding).
pub const TOOLHOST_SOURCE_DIGEST: &str = env!("KATA_TOOLHOST_SOURCE_DIGEST");

/// The most raw bytes one [`Chunk`] carries: 64 KiB.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// The most raw bytes one [`FileBody`] carries, so the largest file one
/// `ReadFile` or `WriteFile` moves: 4 MiB. Its base64 is 5,592,408 characters,
/// which leaves a frame room under [`MAX_FRAME_BYTES`] for a path of any length
/// Linux resolves.
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

/// A worker-assigned request number. The worker assigns every id, so it never
/// parses a name the toolhost chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub u64);

/// A worker-assigned session number: one spawned process group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub u32);

/// Which output pipe a [`ToolhostFrame::Output`] chunk came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
}

/// The signal a [`WorkerFrame::Signal`] sends to a session's whole process group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Interrupt,
    Terminate,
    Kill,
}

/// Everything the worker sends.
///
/// Adjacently tagged (`{"kind": …, "frame": {…}}`), as the provider protocol's
/// frames are: an internally tagged payload would have to accept `kind` as a
/// field, which `deny_unknown_fields` forbids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "frame",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WorkerFrame {
    /// Spawn `[shell or "sh", "-c" or "-lc" when `login`, script]` in a new
    /// session, with cwd `workdir` or `/work`.
    Exec {
        id: RequestId,
        session: SessionId,
        #[serde(deserialize_with = "required_option")]
        shell: Option<String>,
        login: bool,
        script: String,
        #[serde(deserialize_with = "required_option")]
        workdir: Option<String>,
    },
    /// Write to a session's stdin pipe, closing it after when `close`.
    Stdin {
        session: SessionId,
        data_b64: Chunk,
        close: bool,
    },
    /// Signal a session's process group.
    Signal {
        session: SessionId,
        signal: SignalKind,
    },
    /// SIGKILL every descendant of the toolhost and reap them, until `/proc`
    /// lists none; answered `Done` after the `Exited` of every session that was
    /// live, or `Error` with this id when the kill's deadline passed first.
    KillAll { id: RequestId },
    /// Read a file's bytes; answered `FileBytes`, or `FileError` (EFBIG for a
    /// file over [`MAX_FILE_BYTES`]).
    ReadFile { id: RequestId, path: String },
    /// Write a file's bytes through a temp file and a rename, creating parents;
    /// answered `Done` or `FileError`.
    WriteFile {
        id: RequestId,
        path: String,
        data_b64: FileBody,
    },
    /// Remove a file; answered `Done` or `FileError`.
    RemoveFile { id: RequestId, path: String },
    /// Do what `KillAll` does, answer `Bye`, and exit; `Error` with this id
    /// instead of `Bye` when the kill's deadline passed first.
    Shutdown { id: RequestId },
}

/// Everything the toolhost sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "frame",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ToolhostFrame {
    /// The first frame, unsolicited.
    Hello(Hello),
    /// An `Exec` spawned; `note` says what the toolhost substituted, if anything.
    Started {
        id: RequestId,
        session: SessionId,
        pid: u32,
        #[serde(deserialize_with = "required_option")]
        note: Option<String>,
    },
    /// An `Exec` did not spawn.
    SpawnFailed {
        id: RequestId,
        session: SessionId,
        errno: i32,
        message: String,
    },
    /// Output as produced.
    Output {
        session: SessionId,
        stream: Stream,
        data_b64: Chunk,
    },
    /// A session ended: both pipes reached EOF and its process was reaped.
    Exited {
        session: SessionId,
        #[serde(deserialize_with = "required_option")]
        code: Option<i32>,
        #[serde(deserialize_with = "required_option")]
        signal: Option<i32>,
    },
    /// A `Stdin` or `Signal` named a session that is not live.
    SessionGone { session: SessionId },
    /// A `ReadFile` answer; `None` means the file does not exist.
    FileBytes {
        id: RequestId,
        #[serde(deserialize_with = "required_option")]
        data_b64: Option<FileBody>,
    },
    /// A file verb failed.
    FileError {
        id: RequestId,
        errno: i32,
        message: String,
    },
    /// A request without a payload answer completed. After the `Done` of a
    /// `KillAll`, no process the toolhost started is alive.
    Done { id: RequestId },
    /// The `Shutdown` answer, written before the toolhost exits.
    Bye { id: RequestId, reaped: u32 },
    /// A frame the toolhost could not decode or does not define, or (with `id`
    /// null and a message naming the session) a `Stdin` whose bytes the toolhost
    /// dropped because that session's queue was full: its process is not reading
    /// its stdin, or (with the request's id) a `KillAll` or `Shutdown` whose
    /// kill reached its deadline with a process still listed, after which the
    /// toolhost exits. The worker treats it as a protocol break.
    Error {
        #[serde(deserialize_with = "required_option")]
        id: Option<RequestId>,
        message: String,
    },
}

/// The toolhost's opening statement of what it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol: u32,
    pub source_digest: String,
}

impl Hello {
    /// The hello this build's toolhost sends.
    pub fn current() -> Self {
        Self {
            protocol: TOOLHOST_PROTOCOL_VERSION,
            source_digest: TOOLHOST_SOURCE_DIGEST.to_owned(),
        }
    }

    /// Admit the hello only if it states this build's protocol and source digest.
    ///
    /// # Errors
    /// [`ToolhostMismatch`], protocol first: a different protocol is the more
    /// specific statement of why the frames that follow would not be understood.
    pub fn check(&self) -> Result<(), ToolhostMismatch> {
        let Self {
            protocol,
            source_digest,
        } = self;
        if *protocol != TOOLHOST_PROTOCOL_VERSION {
            return Err(ToolhostMismatch::Protocol {
                stated: *protocol,
                expected: TOOLHOST_PROTOCOL_VERSION,
            });
        }
        if source_digest != TOOLHOST_SOURCE_DIGEST {
            return Err(ToolhostMismatch::SourceDigest {
                stated: source_digest.clone(),
                expected: TOOLHOST_SOURCE_DIGEST,
            });
        }
        Ok(())
    }
}

/// A [`Hello`] that is not this build's toolhost.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolhostMismatch {
    #[error(
        "toolhost_mismatch: the toolhost speaks protocol {stated}, this build speaks {expected}"
    )]
    Protocol { stated: u32, expected: u32 },
    #[error(
        "toolhost_mismatch: the toolhost was built from source {stated}, this build from \
         {expected}; a stale or foreign kata-toolhost is refused before any tool frame"
    )]
    SourceDigest {
        stated: String,
        expected: &'static str,
    },
}

/// Raw bytes on the wire: canonical padded base64, at most [`MAX_CHUNK_BYTES`]
/// raw.
#[derive(Clone, PartialEq, Eq)]
pub struct Chunk(Vec<u8>);

/// The length, not the bytes: a failure message is no place for 64 KiB.
impl std::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chunk({} bytes)", self.0.len())
    }
}

/// A [`Chunk`] over [`MAX_CHUNK_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a toolhost chunk carries at most {MAX_CHUNK_BYTES} bytes; this one carried {0}")]
pub struct ChunkTooLarge(pub usize);

impl Chunk {
    /// # Errors
    /// [`ChunkTooLarge`] above [`MAX_CHUNK_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, ChunkTooLarge> {
        if bytes.len() > MAX_CHUNK_BYTES {
            return Err(ChunkTooLarge(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for Chunk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Chunk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let bytes = decode_base64_within(deserializer, MAX_CHUNK_BYTES, "a toolhost chunk")?;
        Self::new(bytes).map_err(D::Error::custom)
    }
}

/// A whole file's bytes on the wire: canonical padded base64, at most
/// [`MAX_FILE_BYTES`] raw.
#[derive(Clone, PartialEq, Eq)]
pub struct FileBody(Vec<u8>);

/// The length, not the bytes: a failure message is no place for 4 MiB.
impl std::fmt::Debug for FileBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileBody({} bytes)", self.0.len())
    }
}

/// A [`FileBody`] over [`MAX_FILE_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "toolhost_file_too_large: a toolhost file body carries at most {MAX_FILE_BYTES} bytes; \
     this one carried {0}"
)]
pub struct FileTooLarge(pub usize);

impl FileBody {
    /// # Errors
    /// [`FileTooLarge`] above [`MAX_FILE_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, FileTooLarge> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(FileTooLarge(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for FileBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for FileBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let bytes = decode_base64_within(
            deserializer,
            MAX_FILE_BYTES,
            "toolhost_file_too_large: a toolhost file body",
        )?;
        Self::new(bytes).map_err(D::Error::custom)
    }
}

/// Decode canonical padded base64 that should carry at most `cap` raw bytes.
///
/// A string longer than any canonical encoding of `cap` bytes is refused before
/// decoding, which saves the decode; `what` opens that refusal. The length bound
/// is coarse (that many characters can encode up to two bytes over the cap), so
/// the caller's constructor applies the exact cap to what this returns.
fn decode_base64_within<'de, D: Deserializer<'de>>(
    deserializer: D,
    cap: usize,
    what: &str,
) -> Result<Vec<u8>, D::Error> {
    use serde::de::Error as _;
    let encoded = String::deserialize(deserializer)?;
    if encoded.len() > cap.div_ceil(3) * 4 {
        return Err(D::Error::custom(format_args!(
            "{what} carries at most {cap} bytes; this one's base64 is {} characters",
            encoded.len()
        )));
    }
    STANDARD.decode(&encoded).map_err(D::Error::custom)
}

/// Deserialize an `Option` field whose key must be PRESENT (`null` or a value).
/// Naming a `deserialize_with` stops serde from defaulting an absent `Option`
/// key to `None`; the provider protocol's private `required_option` is the same
/// rule for the same reason.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(test)]
mod tests;
