//! The frames between a supervisor and its interpreter process, over the one
//! socket the interpreter holds as its descriptor 0: each frame a big-endian
//! `u32` length and that many bytes of JSON.
//!
//! Neither side trusts a length it reads: a frame longer than [`FRAME_CAP`]
//! ends the read before any of its body is allocated. The supervisor treats
//! everything the interpreter sends as untrusted input (`supervisor`), and the
//! interpreter refuses a frame its parent should never send by ending.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use nanocode_code_mode_engine::{NativeLimits, RuntimeEvent};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, value::RawValue};

/// The longest frame either side reads or writes, in bytes. A cell's tool-call
/// inputs, its tool results and the stored values it writes are charged
/// against no output limit, so this is what bounds one of them on the wire: a
/// cell whose source and tools would exceed it fails before it runs, a tool
/// result that would exceed it reaches the cell as that tool's failure, a cell
/// whose tool-call input or stored values would exceed it fails naming them
/// (the interpreter sends that failure in their place), and an interpreter
/// that sends a longer frame is killed. A cell's stored values cross one at a
/// time, as it loads them (`Load`, `Loaded`), so what a session has stored is
/// bounded by no frame. It is eight times the engine's per-cell output limit
/// kata installs (`cell_emitted_bytes`, 8 MiB), so one honest content item,
/// JSON-escaped at worst six bytes to one, fits.
///
/// It bounds bytes on the wire, not what decoding a frame takes in the process
/// that reads it. A tool-call input or a content item decodes into
/// `serde_json::Value`, which takes up to 88 times the frame's length for an
/// array of one-key objects, 71 for nested arrays and 16 for an array of
/// zeros, against once for a string (MEASURED, serde_json 1.0.149, 64 MiB
/// frames: 5.6 GiB, 4.5 GiB, 1 GiB, 64 MiB), before the supervisor admits the
/// frame or kills its sender. The supervisor holds at most six decoded frames
/// per interpreter, but the harness holds each admitted tool-call input until
/// its call ends, and a cell's tool calls are bounded only by its event count.
/// So this bounds each frame's decode, and the hosting process's memory is
/// bounded neither against a compromised interpreter nor against an honest
/// cell that passes large inputs to many tool calls at once: those inputs
/// decode there as they did when the engine's own worker thread ran the cell
/// in that process (MEASURED: ten concurrent calls on one array of four
/// million zeros grow it by about 1.26 GB through the interpreter process, and
/// 1.33 GB on the in-thread worker). A lower cap would refuse honest frames:
/// one content item of the whole output limit, JSON-escaped at worst six bytes
/// to one, is 48 MiB.
pub const FRAME_CAP: usize = 64 << 20;

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    /// The stream ended inside a frame.
    Truncated,
    /// A length over [`FRAME_CAP`]: nothing of the body was read.
    Oversize(usize),
    /// The body is not the JSON of a frame this side reads.
    Malformed(serde_json::Error),
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("the stream ended inside a frame"),
            Self::Oversize(length) => {
                write!(
                    f,
                    "a frame of {length} bytes, over the {FRAME_CAP}-byte cap"
                )
            }
            Self::Malformed(error) => write!(f, "a frame that is not one: {error}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

/// Encodes `frame` with its length prefix; `None` when it would exceed
/// [`FRAME_CAP`] (or does not serialize, which no frame type here allows).
pub fn encode(frame: &impl Serialize) -> Option<Vec<u8>> {
    let body = serde_json::to_vec(frame).ok()?;
    let length = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= FRAME_CAP)?;
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&body);
    Some(bytes)
}

/// Reads one frame; `Ok(None)` at a clean end of stream, between frames.
pub fn read<T: DeserializeOwned>(input: &mut impl Read) -> Result<Option<T>, FrameError> {
    let mut prefix = [0_u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        match input.read(&mut prefix[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    let length = u32::from_be_bytes(prefix) as usize;
    if length > FRAME_CAP {
        return Err(FrameError::Oversize(length));
    }
    let mut body = vec![0_u8; length];
    input.read_exact(&mut body).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(error)
        }
    })?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(FrameError::Malformed)
}

/// Writes `bytes`, an [`encode`]d frame, whole.
pub fn write(output: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    output.write_all(bytes)?;
    output.flush()
}

/// What a supervisor sends its interpreter process.
#[derive(Serialize, Deserialize)]
pub enum ToInterpreter {
    /// The first frame, before the interpreter answers anything: the limits
    /// its engine runs every cell under, and the pid of the process that
    /// started it, which it checks is still its parent.
    Init {
        limits: Limits,
        parent: i32,
    },
    /// One cell to run (the engine's `HostCommand::Start`, never journaled),
    /// without its stored values: the interpreter asks for each one the cell
    /// loads (`Load`).
    Start {
        execution_id: u64,
        source: String,
        tools: Vec<Value>,
        prelude: Option<String>,
    },
    /// The answer to the interpreter's last `Load`: the running cell's stored
    /// value of that key, or `None` when it has none.
    Loaded {
        value: Option<Arc<RawValue>>,
    },
    ToolResult {
        execution_id: u64,
        id: u64,
        encoded: String,
        success: bool,
    },
    Hold {
        execution_id: u64,
    },
    Release {
        execution_id: u64,
    },
}

/// What an interpreter process sends its supervisor.
#[derive(Serialize, Deserialize)]
pub enum FromInterpreter {
    /// The interpreter can take a cell: sent once its hardening and its engine
    /// worker are in place, and again once the worker of the cell before has
    /// ended.
    Ready,
    /// The interpreter could not start an engine worker, and ends.
    Refused { message: String },
    /// The running cell loads `key`, which its stored values may hold; its
    /// JavaScript waits for the `Loaded` answer.
    Load { key: String },
    /// One of the running cell's events.
    Event(Event),
}

/// The engine's `NativeLimits`, field for field. [`From`] destructures the
/// engine's struct whole, so a field the engine adds fails this build until it
/// crosses the wire too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    memory_bytes: usize,
    max_stack_bytes: usize,
    thread_stack_bytes: usize,
    cell_wall_nanos: u64,
    cell_emitted_bytes: usize,
    live_workers: usize,
}

impl From<NativeLimits> for Limits {
    fn from(limits: NativeLimits) -> Self {
        let NativeLimits {
            memory_bytes,
            max_stack_bytes,
            thread_stack_bytes,
            cell_wall,
            cell_emitted_bytes,
            live_workers,
        } = limits;
        Self {
            memory_bytes,
            max_stack_bytes,
            thread_stack_bytes,
            cell_wall_nanos: u64::try_from(cell_wall.as_nanos()).unwrap_or(u64::MAX),
            cell_emitted_bytes,
            live_workers,
        }
    }
}

impl From<Limits> for NativeLimits {
    fn from(limits: Limits) -> Self {
        Self {
            memory_bytes: limits.memory_bytes,
            max_stack_bytes: limits.max_stack_bytes,
            thread_stack_bytes: limits.thread_stack_bytes,
            cell_wall: Duration::from_nanos(limits.cell_wall_nanos),
            cell_emitted_bytes: limits.cell_emitted_bytes,
            live_workers: limits.live_workers,
        }
    }
}

/// The engine's `RuntimeEvent`, variant for variant: [`Event::encode`] and
/// [`Event::decode`] match both enums whole, so a variant the engine adds
/// fails this build until it crosses the wire too. A content item travels as
/// its JSON, the shape the engine's own bootstrap hands it over in.
#[derive(Serialize, Deserialize)]
pub enum Event {
    ToolCall {
        cell_id: u64,
        id: u64,
        name: String,
        input: Value,
        host: bool,
    },
    Notify {
        cell_id: u64,
        text: String,
    },
    Content {
        cell_id: u64,
        content: Value,
    },
    Yielded {
        cell_id: u64,
    },
    Done {
        cell_id: u64,
        stored: HashMap<String, Arc<RawValue>>,
    },
    Error {
        cell_id: u64,
        message: String,
        stored: HashMap<String, Arc<RawValue>>,
    },
    Held {
        cell_id: u64,
    },
    Replayed {
        cell_id: u64,
    },
    Diverged {
        cell_id: u64,
        reason: String,
    },
}

impl Event {
    /// The cell this event is of.
    pub const fn cell_id(&self) -> u64 {
        match self {
            Self::ToolCall { cell_id, .. }
            | Self::Notify { cell_id, .. }
            | Self::Content { cell_id, .. }
            | Self::Yielded { cell_id }
            | Self::Done { cell_id, .. }
            | Self::Error { cell_id, .. }
            | Self::Held { cell_id }
            | Self::Replayed { cell_id }
            | Self::Diverged { cell_id, .. } => *cell_id,
        }
    }

    /// The wire form of `event`; `Err` for a content item that does not
    /// serialize (nanocode refuses to write an image `file_id` it does not
    /// accept).
    pub fn encode(event: RuntimeEvent) -> Result<Self, serde_json::Error> {
        Ok(match event {
            RuntimeEvent::ToolCall {
                cell_id,
                id,
                name,
                input,
                host,
            } => Self::ToolCall {
                cell_id,
                id,
                name,
                input,
                host,
            },
            RuntimeEvent::Notify { cell_id, text } => Self::Notify { cell_id, text },
            RuntimeEvent::Content { cell_id, content } => Self::Content {
                cell_id,
                content: serde_json::to_value(&content)?,
            },
            RuntimeEvent::Yielded { cell_id } => Self::Yielded { cell_id },
            RuntimeEvent::Done { cell_id, stored } => Self::Done { cell_id, stored },
            RuntimeEvent::Error {
                cell_id,
                message,
                stored,
            } => Self::Error {
                cell_id,
                message,
                stored,
            },
            RuntimeEvent::Held { cell_id } => Self::Held { cell_id },
            RuntimeEvent::Replayed { cell_id } => Self::Replayed { cell_id },
            RuntimeEvent::Diverged { cell_id, reason } => Self::Diverged { cell_id, reason },
        })
    }

    /// The engine's event; `Err` for a content item that is not one.
    pub fn decode(self) -> Result<RuntimeEvent, serde_json::Error> {
        Ok(match self {
            Self::ToolCall {
                cell_id,
                id,
                name,
                input,
                host,
            } => RuntimeEvent::ToolCall {
                cell_id,
                id,
                name,
                input,
                host,
            },
            Self::Notify { cell_id, text } => RuntimeEvent::Notify { cell_id, text },
            Self::Content { cell_id, content } => RuntimeEvent::Content {
                cell_id,
                content: serde_json::from_value(content)?,
            },
            Self::Yielded { cell_id } => RuntimeEvent::Yielded { cell_id },
            Self::Done { cell_id, stored } => RuntimeEvent::Done { cell_id, stored },
            Self::Error {
                cell_id,
                message,
                stored,
            } => RuntimeEvent::Error {
                cell_id,
                message,
                stored,
            },
            Self::Held { cell_id } => RuntimeEvent::Held { cell_id },
            Self::Replayed { cell_id } => RuntimeEvent::Replayed { cell_id },
            Self::Diverged { cell_id, reason } => RuntimeEvent::Diverged { cell_id, reason },
        })
    }
}
