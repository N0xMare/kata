//! Starts a shipped binary as a Code Mode interpreter process, as kata's
//! supervisor does (`kata_code_mode_host::INTERPRETER_ARGS`, a socket on
//! descriptor 0, an empty environment), and drives one cell through it by
//! hand: the frames are written and read here, a big-endian `u32` length and
//! JSON, not by kata's encoder. Included by the shipped binaries' tests.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn send(socket: &mut UnixStream, frame: &Value) {
    let body = serde_json::to_vec(frame).expect("JSON");
    socket
        .write_all(&u32::try_from(body.len()).expect("a u32").to_be_bytes())
        .and_then(|()| socket.write_all(&body))
        .expect("a frame to the interpreter");
}

fn read(socket: &mut UnixStream) -> Value {
    let mut prefix = [0_u8; 4];
    socket.read_exact(&mut prefix).expect("a frame's length");
    let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    socket.read_exact(&mut body).expect("a frame's body");
    serde_json::from_slice(&body).expect("a frame is JSON")
}

/// Runs one cell that loads a stored value and notifies it in `binary` started
/// as an interpreter, and checks what the process answered and what the kernel
/// says of it: its `Ready`, the cell's `Load` (answered here), its notification
/// of the answer and `Done`, its `Ready` again, its command line naming
/// `binary`, its environment unreadable to this process (it is not dumpable),
/// and, once the socket closes, its exit with status 0.
pub fn a_cell_runs_in(binary: &str) {
    let (mut ours, theirs) = UnixStream::pair().expect("a socket pair");
    let mut child = Command::new(binary)
        .args(kata_code_mode_host::INTERPRETER_ARGS)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the binary starts");
    send(
        &mut ours,
        &json!({"Init": {
            "limits": {
                "memory_bytes": 64 << 20,
                "max_stack_bytes": 1 << 20,
                "thread_stack_bytes": 8 << 20,
                "cell_wall_nanos": 10_000_000_000_u64,
                "cell_emitted_bytes": 1 << 20,
                "live_workers": 1,
            },
            "parent": std::process::id(),
        }}),
    );
    assert_eq!(
        read(&mut ours),
        json!("Ready"),
        "{binary}: its first answer"
    );
    send(
        &mut ours,
        &json!({"Start": {
            "execution_id": 1,
            "source": "notify(\"from the shipped binary: \" + load(\"k\"));",
            "tools": [],
            "prelude": null,
        }}),
    );
    assert_eq!(
        read(&mut ours),
        json!({"Load": {"key": "k"}}),
        "{binary}: the cell asks for its stored value"
    );
    send(&mut ours, &json!({"Loaded": {"value": 7}}));
    assert_eq!(
        read(&mut ours),
        json!({"Event": {"Notify": {"cell_id": 1, "text": "from the shipped binary: 7"}}})
    );
    assert_eq!(
        read(&mut ours),
        json!({"Event": {"Done": {"cell_id": 1, "stored": {}}}})
    );
    assert_eq!(
        read(&mut ours),
        json!("Ready"),
        "{binary}: ready for the next cell"
    );
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", child.id())).expect("its cmdline");
    assert!(
        cmdline.starts_with(binary.as_bytes()),
        "{}",
        String::from_utf8_lossy(&cmdline)
    );
    assert_eq!(
        std::fs::read(format!("/proc/{}/environ", child.id())).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "{binary}: not dumpable"
    );
    drop(ours);
    let status = child.wait().expect("reap it");
    assert!(status.success(), "{binary}: {status:?}");
}
