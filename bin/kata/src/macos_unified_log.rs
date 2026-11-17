//! Bounded `tracing` writer for the installed launchd service.
//!
//! launchd can redirect stdout/stderr only to append-only files and provides
//! no rotation contract. A multi-day Kata main therefore writes formatted
//! events directly to Apple's retention-managed unified log under one exact
//! subsystem/category. The C shim is necessary because `os_log_with_type` is
//! a variadic macro, not a directly callable ABI symbol.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_void};
use std::io::Write as _;
use std::ptr::NonNull;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;

pub(crate) const KATA_OS_LOG_SUBSYSTEM: &str = "sh.kata.main";
pub(crate) const KATA_OS_LOG_CATEGORY: &str = "installed-main";

// Apple may truncate long records itself. Kata applies an earlier explicit
// bound so one hostile tracing field cannot allocate without limit before the
// event reaches that system boundary.
const MAX_FORMATTED_EVENT_BYTES: usize = 16 * 1024;
const TRUNCATED_SUFFIX: &[u8] = b" [kata event truncated]";

unsafe extern "C" {
    fn kata_os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    fn kata_os_log_write(log: *mut c_void, level: u8, message: *const c_char);
    fn kata_os_log_release(log: *mut c_void);
}

#[derive(Clone)]
struct UnifiedLogMakeWriter {
    inner: Arc<UnifiedLogInner>,
}

struct UnifiedLogInner {
    raw: NonNull<c_void>,
}

// SAFETY: Apple documents OSLog as Sendable and its C logging entry points are
// designed for concurrent callers. `raw` is immutable after construction and
// released exactly once when the final Arc is dropped.
unsafe impl Send for UnifiedLogInner {}
// SAFETY: same invariant as the Send implementation above.
unsafe impl Sync for UnifiedLogInner {}

impl Drop for UnifiedLogInner {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `kata_os_log_create`, remains live for this
        // final Arc owner, and the shim releases exactly that OS object.
        unsafe { kata_os_log_release(self.raw.as_ptr()) };
    }
}

impl UnifiedLogMakeWriter {
    fn new() -> Result<Self> {
        let subsystem = CString::new(KATA_OS_LOG_SUBSYSTEM).expect("static subsystem has no NUL");
        let category = CString::new(KATA_OS_LOG_CATEGORY).expect("static category has no NUL");
        // SAFETY: both pointers are valid NUL-terminated strings for the call.
        // Apple specifies that os_log_create returns a retained log object.
        let raw = unsafe { kata_os_log_create(subsystem.as_ptr(), category.as_ptr()) };
        let raw = NonNull::new(raw)
            .ok_or_else(|| anyhow!("Apple unified logging returned a null log object"))?;
        Ok(Self {
            inner: Arc::new(UnifiedLogInner { raw }),
        })
    }
}

impl<'writer> MakeWriter<'writer> for UnifiedLogMakeWriter {
    type Writer = UnifiedLogEventWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        UnifiedLogEventWriter::new(Arc::clone(&self.inner), UnifiedLogLevel::Info)
    }

    fn make_writer_for(&'writer self, metadata: &Metadata<'_>) -> Self::Writer {
        UnifiedLogEventWriter::new(
            Arc::clone(&self.inner),
            UnifiedLogLevel::from_tracing(metadata.level()),
        )
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum UnifiedLogLevel {
    Debug = 0,
    Info = 1,
    Error = 2,
}

impl UnifiedLogLevel {
    fn from_tracing(level: &Level) -> Self {
        match *level {
            Level::TRACE | Level::DEBUG => Self::Debug,
            Level::INFO => Self::Info,
            Level::WARN | Level::ERROR => Self::Error,
        }
    }
}

struct UnifiedLogEventWriter {
    inner: Arc<UnifiedLogInner>,
    level: UnifiedLogLevel,
    event: BoundedEventBytes,
}

struct BoundedEventBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

impl BoundedEventBytes {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(1024),
            truncated: false,
        }
    }

    fn write(&mut self, input: &[u8]) -> usize {
        let payload_bound = MAX_FORMATTED_EVENT_BYTES - TRUNCATED_SUFFIX.len();
        let remaining = payload_bound.saturating_sub(self.bytes.len());
        if remaining == 0 {
            self.truncated |= !input.is_empty();
            return input.len();
        }
        // Inspect at most the remaining payload plus the three trailing bytes
        // needed to see a four-byte UTF-8 scalar in full. This preserves a
        // clean character boundary without allocating in proportion to a
        // hostile oversized `Write` chunk.
        let inspected = input.len().min(remaining.saturating_add(3));
        let text = String::from_utf8_lossy(&input[..inspected]);
        let mut accepted = remaining.min(text.len());
        while !text.is_char_boundary(accepted) {
            accepted -= 1;
        }
        self.bytes.extend_from_slice(&text.as_bytes()[..accepted]);
        self.truncated |= inspected != input.len() || accepted != text.len();
        input.len()
    }

    fn finish(&mut self) -> Vec<u8> {
        while self
            .bytes
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            self.bytes.pop();
        }
        if self.truncated {
            self.bytes.extend_from_slice(TRUNCATED_SUFFIX);
        }
        // Dynamic event fields can contain NULs, while C strings cannot. A
        // visible replacement preserves record boundaries without panicking.
        self.bytes.iter_mut().for_each(|byte| {
            if *byte == 0 {
                *byte = b'?';
            }
        });
        std::mem::take(&mut self.bytes)
    }
}

impl UnifiedLogEventWriter {
    fn new(inner: Arc<UnifiedLogInner>, level: UnifiedLogLevel) -> Self {
        Self {
            inner,
            level,
            event: BoundedEventBytes::new(),
        }
    }
}

impl std::io::Write for UnifiedLogEventWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        // Reporting the full input consumed tells tracing's formatter that the
        // deliberate event cap is a policy decision, not an I/O failure.
        Ok(self.event.write(input))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for UnifiedLogEventWriter {
    fn drop(&mut self) {
        let bytes = self.event.finish();
        if bytes.is_empty() {
            return;
        }
        let Ok(message) = CString::new(bytes) else {
            return;
        };
        // SAFETY: the Arc keeps `raw` alive; `message` is NUL-terminated; the
        // level is the private enum understood by the C shim.
        unsafe {
            kata_os_log_write(self.inner.raw.as_ptr(), self.level as u8, message.as_ptr());
        }
    }
}

pub(crate) fn make_writer() -> Result<BoxMakeWriter> {
    UnifiedLogMakeWriter::new().map(BoxMakeWriter::new)
}

pub(crate) fn write_startup_error(message: &str) -> Result<()> {
    let writer = UnifiedLogMakeWriter::new()?;
    let mut event = UnifiedLogEventWriter::new(writer.inner, UnifiedLogLevel::Error);
    event.write_all(message.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatted_event_bound_is_exact_and_nonvacuous() {
        let mut event = BoundedEventBytes::new();
        let oversized = vec![b'x'; MAX_FORMATTED_EVENT_BYTES * 2];
        assert_eq!(event.write(&oversized), oversized.len());

        let finished = event.finish();
        assert_eq!(finished.len(), MAX_FORMATTED_EVENT_BYTES);
        assert!(finished.ends_with(TRUNCATED_SUFFIX));
        assert!(
            finished[..MAX_FORMATTED_EVENT_BYTES - TRUNCATED_SUFFIX.len()]
                .iter()
                .all(|byte| *byte == b'x')
        );
    }

    #[test]
    fn formatted_event_sanitizes_nuls_and_trims_record_terminators() {
        let mut event = BoundedEventBytes::new();
        event.write(b"one\0two\r\n");
        assert_eq!(event.finish(), b"one?two");
    }

    #[test]
    fn formatted_event_never_splits_a_multibyte_utf8_code_point() {
        let mut event = BoundedEventBytes::new();
        let payload_bound = MAX_FORMATTED_EVENT_BYTES - TRUNCATED_SUFFIX.len();
        let prefix = vec![b'x'; payload_bound - 1];
        event.write(&prefix);
        event.write("é and the rest of the event".as_bytes());

        let finished = event.finish();
        assert!(finished.len() <= MAX_FORMATTED_EVENT_BYTES);
        assert!(finished.ends_with(TRUNCATED_SUFFIX));
        assert!(std::str::from_utf8(&finished).is_ok());
    }
}
