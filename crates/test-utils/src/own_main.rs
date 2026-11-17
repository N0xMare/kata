//! A spawned installed main's API endpoint, proven to be that main's own.
//!
//! A main given `[api] bind = "127.0.0.1:0"` binds an ephemeral port and, still
//! holding that listener, takes its data directory's authority lock and writes
//! `<data_dir>/main.lock`: its pid, a `process_generation` minted for that
//! process, and the bound `control_endpoint`. Its `GET /api/v1/system/status`
//! answers the same `process_generation`. [`await_own_main`] returns an
//! endpoint only once the lock names the child's pid AND the endpoint the lock
//! names answers that lock's generation, so the answer is the child's own: no
//! other process holds that generation, and the port was the child's from
//! before the lock was written.
//!
//! Refused — the wait goes on, and its error names the last refusal:
//! * a `main.lock` another pid wrote: a previous boot's, which a restart on the
//!   same data directory finds before the new main rewrites it;
//! * an endpoint that does not answer, or answers anything but `200` carrying
//!   the lock's generation.
//!
//! A child that ended ends the wait at once ([`OwnMainError::Ended`]).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long one status request may take before the poll counts it unanswered.
const REQUEST_BOUND: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The spawned main as its spawner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildState {
    /// Still running, under this pid.
    Running { pid: u32 },
    /// Ended; the exit as the spawner observed it.
    Ended(String),
}

/// Why [`await_own_main`] returned no endpoint.
#[derive(Debug, thiserror::Error)]
pub enum OwnMainError {
    /// The child ended before an answer proved to be its own.
    #[error("the main ended ({exit}) before it answered as itself; last observation: {last}")]
    Ended { exit: String, last: String },
    /// No answer proved to be the child's own before the deadline.
    #[error("the main did not answer as itself within {timeout:?}; last observation: {last}")]
    Timeout { timeout: Duration, last: String },
}

/// Wait until the main whose state `child` reports answers as itself at the
/// endpoint its own `<data_dir>/main.lock` records; return that endpoint
/// (`http://127.0.0.1:<port>`).
///
/// # Errors
/// [`OwnMainError::Ended`] as soon as `child` reports an end;
/// [`OwnMainError::Timeout`] once `timeout` passes without such an answer.
pub fn await_own_main(
    data_dir: &Path,
    mut child: impl FnMut() -> ChildState,
    timeout: Duration,
) -> Result<String, OwnMainError> {
    let deadline = Instant::now() + timeout;
    let mut last = String::from("no poll completed");
    loop {
        let pid = match child() {
            ChildState::Running { pid } => pid,
            ChildState::Ended(exit) => return Err(OwnMainError::Ended { exit, last }),
        };
        match own_endpoint(data_dir, pid) {
            Ok(endpoint) => return Ok(endpoint),
            Err(observation) => last = observation,
        }
        if Instant::now() >= deadline {
            return Err(OwnMainError::Timeout { timeout, last });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The endpoint `pid`'s lock records, if it answers that lock's generation;
/// otherwise what refused it.
fn own_endpoint(data_dir: &Path, pid: u32) -> Result<String, String> {
    let path = data_dir.join("main.lock");
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} unreadable: {error}", path.display()))?;
    // The main truncates and rewrites the record in place, so a read can land
    // mid-write; an unparseable record is one more poll, not a verdict.
    let record: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| format!("{} is not a whole record yet: {error}", path.display()))?;
    let locked_pid = record["pid"].as_u64();
    if locked_pid != Some(u64::from(pid)) {
        return Err(format!(
            "{} names pid {locked_pid:?}, not the child's {pid}",
            path.display()
        ));
    }
    let generation = record["process_generation"]
        .as_str()
        .ok_or_else(|| format!("{} names no process_generation", path.display()))?;
    let endpoint = record["control_endpoint"]
        .as_str()
        .ok_or_else(|| format!("{} names no control_endpoint", path.display()))?;
    let answered = answered_generation(endpoint)?;
    if answered != generation {
        return Err(format!(
            "{endpoint} answered process_generation {answered:?}, not the child's {generation:?}"
        ));
    }
    Ok(endpoint.to_owned())
}

/// The `process_generation` that `endpoint`'s `GET /api/v1/system/status`
/// answers, read over a plain socket so the check shares no code with kata's
/// client.
fn answered_generation(endpoint: &str) -> Result<String, String> {
    let addr: SocketAddr = endpoint
        .strip_prefix("http://")
        .and_then(|authority| authority.parse().ok())
        .ok_or_else(|| format!("control_endpoint {endpoint:?} is not http://<ip>:<port>"))?;
    let unanswered = |error: std::io::Error| format!("{endpoint} did not answer: {error}");
    let mut stream = TcpStream::connect_timeout(&addr, REQUEST_BOUND).map_err(unanswered)?;
    stream
        .set_read_timeout(Some(REQUEST_BOUND))
        .map_err(unanswered)?;
    stream
        .set_write_timeout(Some(REQUEST_BOUND))
        .map_err(unanswered)?;
    let request =
        format!("GET /api/v1/system/status HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(unanswered)?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(unanswered)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{endpoint} answered no whole HTTP response"))?;
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(format!("{endpoint} answered {status:?}"));
    }
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|status| status["process_generation"].as_str().map(str::to_owned))
        .ok_or_else(|| format!("{endpoint} answered no process_generation"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use super::{ChildState, OwnMainError, await_own_main};

    /// A loopback server that answers every request `200` with a status body
    /// carrying `generation` — a stand-in for whatever holds the port. Its
    /// listener lives as long as the test process.
    fn status_responder(generation: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let body = serde_json::json!({ "process_generation": generation }).to_string();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                // The whole request head, so closing after the answer
                // discards nothing unread (which would reset the connection).
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n")
                    && stream.read(&mut byte).is_ok_and(|n| n == 1)
                {
                    request.push(byte[0]);
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        endpoint
    }

    fn write_lock(data_dir: &Path, pid: u32, generation: &str, endpoint: &str) {
        let record = serde_json::json!({
            "pid": pid,
            "process_generation": generation,
            "control_endpoint": endpoint,
        });
        std::fs::write(data_dir.join("main.lock"), format!("{record}\n")).unwrap();
    }

    /// A real child process to stand in for the main.
    fn sleeper() -> Child {
        Command::new("sleep").arg("30").spawn().unwrap()
    }

    fn state_of(child: &mut Child) -> ChildState {
        match child.try_wait().unwrap() {
            None => ChildState::Running { pid: child.id() },
            Some(status) => ChildState::Ended(status.to_string()),
        }
    }

    /// **The child's own answer is its endpoint.** The lock names the child's
    /// pid and the endpoint, and the endpoint answers the lock's generation.
    #[test]
    fn the_childs_own_answer_is_its_endpoint() {
        let data = tempfile::tempdir().unwrap();
        let mut child = sleeper();
        let endpoint = status_responder("G-child");
        write_lock(data.path(), child.id(), "G-child", &endpoint);
        let found = await_own_main(data.path(), || state_of(&mut child), Duration::from_secs(5));
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(found.unwrap(), endpoint);
    }

    /// **An answer carrying another generation is not the child's.** The lock
    /// is the child's, but whatever answers at its endpoint holds another
    /// generation: the wait refuses it until the deadline, naming both.
    ///
    /// **Would red if:** the wait accepted any answer at the locked endpoint
    /// (watched: `Ok("http://127.0.0.1:<port>")`).
    #[test]
    fn an_answer_carrying_another_generation_is_not_the_childs() {
        let data = tempfile::tempdir().unwrap();
        let mut child = sleeper();
        let endpoint = status_responder("G-foreign");
        write_lock(data.path(), child.id(), "G-child", &endpoint);
        let found = await_own_main(data.path(), || state_of(&mut child), Duration::from_secs(2));
        child.kill().unwrap();
        child.wait().unwrap();
        let Err(OwnMainError::Timeout { last, .. }) = found else {
            panic!("a foreign answer was accepted: {found:?}");
        };
        assert!(
            last.contains("\"G-foreign\", not the child's \"G-child\""),
            "{last}"
        );
    }

    /// **A lock another pid wrote is not the child's.** A previous boot's
    /// record, its endpoint still answering that boot's generation: the wait
    /// refuses it until the deadline, naming both pids.
    ///
    /// **Would red if:** the wait read any pid's record as the child's
    /// (watched: `Ok("http://127.0.0.1:<port>")`).
    #[test]
    fn a_lock_another_pid_wrote_is_not_the_childs() {
        let data = tempfile::tempdir().unwrap();
        let mut child = sleeper();
        let endpoint = status_responder("G-previous");
        let previous = std::process::id();
        write_lock(data.path(), previous, "G-previous", &endpoint);
        let found = await_own_main(data.path(), || state_of(&mut child), Duration::from_secs(2));
        let pid = child.id();
        child.kill().unwrap();
        child.wait().unwrap();
        let Err(OwnMainError::Timeout { last, .. }) = found else {
            panic!("another pid's lock was read as the child's: {found:?}");
        };
        assert!(
            last.contains(&format!(
                "names pid Some({previous}), not the child's {pid}"
            )),
            "{last}"
        );
    }

    /// **A child that ended ends the wait at once**, not at its deadline.
    ///
    /// **Would red if:** the wait polled on past the child's end (watched: the
    /// 20 s deadline spent, `Timeout`).
    #[test]
    fn a_child_that_ended_ends_the_wait_at_once() {
        let data = tempfile::tempdir().unwrap();
        let mut child = Command::new("true").spawn().unwrap();
        child.wait().unwrap();
        let started = Instant::now();
        let found = await_own_main(
            data.path(),
            || state_of(&mut child),
            Duration::from_secs(20),
        );
        assert!(
            matches!(found, Err(OwnMainError::Ended { .. })),
            "{found:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}
