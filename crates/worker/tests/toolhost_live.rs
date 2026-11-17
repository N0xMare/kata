//! `kata-toolhost` as the init of a REAL rootless container: bound read-only at
//! `/.kata` from the provider entry's `toolhost/`, spoken to over the worker's live
//! FIFOs, and torn down with the attempt.
//!
//! # What these cells prove, and against what
//!
//! The toolhost is the one long-lived process kata places in a nanocode agent
//! capsule (a rootless runtime cannot exec a second one into it — see
//! `kata_provider_protocol::OciStdio`), so every claim the tool-host construct makes
//! is a claim about a process tree inside a container. Each cell drives the toolhost
//! through a TEST-ONLY adapter double — this file's [`Toolhost`], which speaks the
//! frames of `kata_toolhost_protocol` and nothing else — and reads its verdict off
//! something that does not share the code under test: the guest's own answers to a
//! shell command (its stdout, stderr and exit code), the host's `/proc`, the
//! container's `cgroup.procs` read straight from the kernel's hierarchy, the attempt
//! root's files on the host, and the pinned runtime's own `state`. The real nanocode
//! adapter driving the same toolhost in the same capsule is `nanocode_capsule_live`'s.
//!
//! The rig (`common/toolhost_capsule.rs`) stages the provider entry exactly as an
//! operator's would hold it: the freshly built `kata-provider-youki` beside
//! `toolhost/kata-toolhost`, the static binary `cargo build -p kata-toolhost --target
//! x86_64-unknown-linux-musl` produced (or, for the digest-mismatch cell, a stand-in
//! init in its place).
//!
//! # It REFUSES on a host that cannot prove containment
//!
//! As its OCI siblings: no certified youki, no installed AppArmor profile or no
//! delegated scope is a FAILURE naming the refusal, never a skip.

#![cfg(target_os = "linux")]

mod common;
#[path = "common/toolhost_capsule.rs"]
#[allow(dead_code)]
mod toolhost_capsule;

use std::time::Duration;

use kata_toolhost_protocol::{
    FRAME_HEADER_BYTES, FileBody, Hello, RequestId, SessionId, Stream, ToolhostFrame,
    ToolhostMismatch, WorkerFrame, body_len, decode_frame, encode_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use toolhost_capsule::{
    BUSYBOX, Placed, Rig, cgroup_tasks, delegated, eventually, namespace_pid, stand_in_toolhost,
};

impl Rig {
    /// Place the capsule and speak to its init through this file's double.
    async fn launch(&self, tag: &str) -> Launched {
        let mut placed = self.place(tag).await;
        let toolhost = Toolhost {
            stdin: Some(placed.process.take_stdin().expect("the toolhost's stdin")),
            stdout: placed.process.take_stdout().expect("the toolhost's stdout"),
            next_id: 0,
        };
        Launched { toolhost, placed }
    }
}

/// One launched capsule: the double, and the placed capsule it speaks to.
struct Launched {
    toolhost: Toolhost,
    placed: Placed,
}

impl Launched {
    /// The init's host pid, by the pinned runtime.
    fn init_pid(&self) -> u32 {
        self.placed.init_pid()
    }

    /// The kata-owned parent cgroup of this container, found from the kernel's view.
    fn cgroup(&self) -> std::path::PathBuf {
        self.placed.cgroup()
    }

    /// Wait for the init's exit, tear down, and answer the exit status. The teardown
    /// must be CONFIRMED.
    async fn finish(mut self) -> std::process::ExitStatus {
        let exit = tokio::time::timeout(Duration::from_secs(30), self.placed.process.wait())
            .await
            .expect("the toolhost exits within 30s")
            .expect("the terminal frame decodes");
        let teardown =
            kata_worker::interactive_capsule::InteractiveTeardown::teardown(self.placed.placement)
                .await;
        assert!(
            teardown.is_confirmed(),
            "teardown not confirmed: {teardown:?}"
        );
        exit
    }
}

/// The test-only adapter double: the worker's end of the toolhost protocol, framed
/// with the protocol crate's own codec.
struct Toolhost {
    stdin: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    stdout: Box<dyn AsyncRead + Send + Unpin>,
    next_id: u64,
}

impl Toolhost {
    fn id(&mut self) -> RequestId {
        self.next_id += 1;
        RequestId(self.next_id)
    }

    async fn send(&mut self, frame: &WorkerFrame) {
        let bytes = encode_frame(frame).expect("a worker frame encodes");
        let stdin = self
            .stdin
            .as_mut()
            .expect("the toolhost's stdin is still open");
        stdin.write_all(&bytes).await.expect("the frame is written");
        stdin.flush().await.expect("the frame is flushed");
    }

    /// The next frame, or `None` at a clean end of stream. Bounded: a toolhost that
    /// goes silent fails the cell naming the wait rather than hanging it.
    async fn next(&mut self) -> Option<ToolhostFrame> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut header = [0u8; FRAME_HEADER_BYTES];
            match self.stdout.read_exact(&mut header).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
                Err(error) => panic!("reading the toolhost's stdout failed: {error}"),
            }
            let len = body_len(header).expect("the toolhost's frame header is in bounds");
            let mut body = vec![0u8; len];
            self.stdout
                .read_exact(&mut body)
                .await
                .expect("the toolhost's frame body arrives whole");
            Some(decode_frame(&body).expect("the toolhost's frame decodes"))
        })
        .await
        .expect("the toolhost answered within 30s")
    }

    /// Read the opening `Hello`. Nothing else may come first.
    async fn hello(&mut self) -> Hello {
        match self.next().await {
            Some(ToolhostFrame::Hello(hello)) => hello,
            other => panic!("the toolhost's first frame is not a Hello: {other:?}"),
        }
    }

    /// Read the `Hello` and admit it as this build's.
    async fn admit(&mut self) {
        self.hello()
            .await
            .check()
            .unwrap_or_else(|mismatch| panic!("the toolhost is not this build's: {mismatch}"));
    }

    /// Send `frame` and answer the next frame.
    async fn ask(&mut self, frame: WorkerFrame) -> ToolhostFrame {
        self.send(&frame).await;
        self.next()
            .await
            .expect("an answer before the end of stream")
    }

    /// Start `script` under `sh -c` as `session`; answer the `Started` pid (a pid of
    /// the capsule's own namespace).
    async fn exec(&mut self, session: u32, script: &str) -> u32 {
        self.exec_as(session, script, false).await
    }

    /// Start `script` under `sh -lc` (`login`) or `sh -c` as `session`; answer the
    /// `Started` pid.
    async fn exec_as(&mut self, session: u32, script: &str, login: bool) -> u32 {
        let id = self.id();
        match self
            .ask(WorkerFrame::Exec {
                id,
                session: SessionId(session),
                shell: None,
                login,
                script: script.to_owned(),
                workdir: None,
            })
            .await
        {
            ToolhostFrame::Started {
                id: answered,
                pid,
                note: None,
                ..
            } if answered == id => pid,
            other => panic!("Exec of session {session} was answered {other:?}"),
        }
    }

    /// Read until `session`'s `Exited`: (stdout, stderr, code, signal).
    async fn drain(&mut self, session: u32) -> (String, String, Option<i32>, Option<i32>) {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        loop {
            match self.next().await {
                Some(ToolhostFrame::Output {
                    session: from,
                    stream,
                    data_b64,
                }) if from == SessionId(session) => match stream {
                    Stream::Stdout => stdout.extend(data_b64.as_bytes()),
                    Stream::Stderr => stderr.extend(data_b64.as_bytes()),
                },
                Some(ToolhostFrame::Exited {
                    session: from,
                    code,
                    signal,
                }) if from == SessionId(session) => {
                    return (
                        String::from_utf8_lossy(&stdout).into_owned(),
                        String::from_utf8_lossy(&stderr).into_owned(),
                        code,
                        signal,
                    );
                }
                other => panic!("while draining session {session}: {other:?}"),
            }
        }
    }

    /// Read until the first `Output` of `session` carrying `marker`.
    async fn output_until(&mut self, session: u32, marker: &str) -> String {
        let mut seen = Vec::new();
        loop {
            match self.next().await {
                Some(ToolhostFrame::Output {
                    session: from,
                    data_b64,
                    ..
                }) if from == SessionId(session) => {
                    seen.extend(data_b64.as_bytes());
                    if String::from_utf8_lossy(&seen).contains(marker) {
                        return String::from_utf8_lossy(&seen).into_owned();
                    }
                }
                other => panic!("while awaiting {marker:?} from session {session}: {other:?}"),
            }
        }
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }
}

// ---------------------------------------------------------------------------
// The probe: the mount class, before anything is built on it
// ---------------------------------------------------------------------------

/// **The provider entry's `toolhost/` directory, bound read-only at `/.kata`, holds the
/// container's init.** The toolhost's own `Hello` arriving on the worker's FIFO is the
/// guest-side proof that `/.kata/kata-toolhost` exec'd; the host's `/proc` says the
/// process is PID 1 of its own namespace and is the toolhost; closing its stdin ends it
/// with exit 0.
///
/// **Would red if:** the bundle bound no `/.kata` (the init's exec fails and no `Hello`
/// arrives — watched RED that way before the mount class existed), the provider created
/// no `/.kata` mount point under the read-only rootfs (youki refuses the mount), the
/// bind carried `noexec` (the exec fails `EACCES`), or the init were anything but the
/// toolhost.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn the_toolhost_dir_bind_lands_and_execs_as_init() {
    delegated("the_toolhost_dir_bind_lands_and_execs_as_init", async {
        let rig = Rig::new();
        let mut launched = rig.launch("toolhost-probe").await;
        launched.toolhost.admit().await;
        let pid = launched.init_pid();
        assert_eq!(
            namespace_pid(pid),
            Some(1),
            "the toolhost is not PID 1 of its own namespace"
        );
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).expect("the init's comm");
        assert_eq!(
            comm.trim(),
            "kata-toolhost",
            "the capsule's init is not the toolhost"
        );
        launched.toolhost.close_stdin();
        let exit = launched.finish().await;
        assert!(
            exit.success(),
            "stdin EOF must end the toolhost with 0; got {exit}"
        );
    });
}

// ---------------------------------------------------------------------------
// The tool-host construct, live
// ---------------------------------------------------------------------------

/// **Every tool process runs inside the capsule, as the toolhost's child.** A session
/// reports, from inside: its cwd is `/work`, `HOME` is `/tmp`, PID 1 is
/// `kata-toolhost`, and `/.kata` holds only `kata-toolhost`. From outside: the
/// container's `cgroup.procs` lists exactly the init and that session's process, and
/// the session's host pid is, in the capsule's pid namespace, the pid its `Started`
/// named.
///
/// MEASURED: with no `HOME` in the bundle the guest would still read `/tmp`, because
/// youki derives `HOME` from the `/etc/passwd` the provider writes (root's home is
/// `/tmp`). So this cell shows the rendered value is the one the guest sees (watched
/// RED with the render moved to `/work`); that kata renders it at all is the bundle
/// golden's to pin.
///
/// **Would red if:** a tool process ran anywhere but the capsule's pid namespace and
/// cgroup (a host-side executor), the toolhost's cwd or rendered `HOME` were not the
/// guest's, or the toolhost directory exposed anything else of the provider entry.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn the_toolhost_runs_as_init_and_execs_inside_the_capsule() {
    delegated(
        "the_toolhost_runs_as_init_and_execs_inside_the_capsule",
        async {
            let rig = Rig::new();
            let mut launched = rig.launch("toolhost-exec").await;
            launched.toolhost.admit().await;
            let started = launched
            .toolhost
            .exec(
                1,
                "pwd; echo \"$HOME\"; cat /proc/1/comm; ls -a /.kata; echo ready; exec sleep 300",
            )
            .await;
            let report = launched.toolhost.output_until(1, "ready").await;
            assert_eq!(
                report, "/work\n/tmp\nkata-toolhost\n.\n..\nkata-toolhost\nready\n",
                "the session's own report"
            );
            let init = launched.init_pid();
            let tasks = eventually(
                Duration::from_secs(10),
                "the cgroup lists the init and one session",
                || cgroup_tasks(&launched.cgroup()),
                |tasks| tasks.len() == 2,
            )
            .await;
            let session = tasks
                .iter()
                .copied()
                .find(|pid| *pid != init)
                .unwrap_or_else(|| panic!("the init is not among the container's tasks {tasks:?}"));
            assert!(tasks.contains(&init), "{tasks:?} lacks the init {init}");
            assert_eq!(
                namespace_pid(session),
                Some(started),
                "the cgroup's other task is the session `Started` named"
            );
            let id = launched.toolhost.id();
            launched.toolhost.send(&WorkerFrame::Shutdown { id }).await;
            let frames = [
                launched.toolhost.next().await,
                launched.toolhost.next().await,
            ];
            assert!(
                matches!(
                    frames,
                    [
                        Some(ToolhostFrame::Exited {
                            signal: Some(9),
                            ..
                        }),
                        Some(ToolhostFrame::Bye { .. })
                    ]
                ),
                "{frames:?}"
            );
            let exit = launched.finish().await;
            assert!(exit.success(), "{exit}");
        },
    );
}

/// **A login exec runs in the same environment as a plain one, inside a real
/// capsule.** nanocode's `exec_command` declares `login` "Defaults to true", and the
/// seam follows it, so a model that omits it gets `sh -lc`. The capsule's rootfs
/// carries no `/etc/profile` and its `HOME` (`/tmp`) no `.profile`, so the login
/// shell keeps the bundle's `PATH`, `HOME` and cwd: the two sessions report the same
/// environment, and the login one finds `git` on that `PATH`.
///
/// **Would red if:** a login shell in the capsule replaced the bundle's `PATH` (a
/// profile the rootfs gained), so a model's default exec would lose the closure's
/// tools.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_login_exec_keeps_the_capsule_environment() {
    delegated("a_login_exec_keeps_the_capsule_environment", async {
        let rig = Rig::new();
        let mut launched = rig.launch("toolhost-login").await;
        launched.toolhost.admit().await;
        let report = "echo \"$PATH\"; echo \"$HOME\"; pwd; ls -a /etc";
        launched.toolhost.exec_as(1, report, false).await;
        let plain = launched.toolhost.drain(1).await;
        launched
            .toolhost
            .exec_as(2, &format!("{report}; command -v sh"), true)
            .await;
        let login = launched.toolhost.drain(2).await;
        assert_eq!(plain.2, Some(0), "the plain exec: {plain:?}");
        assert_eq!(login.2, Some(0), "the login exec: {login:?}");
        assert!(
            login.0.starts_with(&plain.0),
            "the login shell reports the plain one's environment: plain {plain:?}, login \
             {login:?}"
        );
        assert!(
            !plain.0.contains("profile"),
            "the rootfs carries no profile: {plain:?}"
        );
        let id = launched.toolhost.id();
        launched.toolhost.send(&WorkerFrame::Shutdown { id }).await;
        assert!(
            matches!(
                launched.toolhost.next().await,
                Some(ToolhostFrame::Bye { .. })
            ),
            "Shutdown is answered Bye"
        );
        let exit = launched.finish().await;
        assert!(exit.success(), "{exit}");
    });
}

/// **The toolhost's directory and the store are read-only to every tool call.** A
/// `WriteFile` into `/.kata`, over `/.kata/kata-toolhost` and into the closure's store
/// path, and a `RemoveFile` of the toolhost, each answer `FileError` EROFS from the
/// kernel; a session's `touch /.kata/x` fails "Read-only file system". The control: a
/// `WriteFile` to `/work` lands, read back from the attempt root on the host.
///
/// **Would red if:** the `/.kata` bind were writable (a tool call could replace the
/// capsule's own init or plant a file beside it), or the store bind were.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_write_to_the_toolhost_mount_or_the_store_is_erofs() {
    delegated(
        "a_write_to_the_toolhost_mount_or_the_store_is_erofs",
        async {
            let rig = Rig::new();
            let mut launched = rig.launch("toolhost-erofs").await;
            launched.toolhost.admit().await;
            let body = || FileBody::new(b"planted".to_vec()).unwrap();
            let writes = [
                "/.kata/planted".to_owned(),
                "/.kata/kata-toolhost".to_owned(),
                format!("{BUSYBOX}/planted"),
            ];
            for path in writes {
                let id = launched.toolhost.id();
                let answer = launched
                    .toolhost
                    .ask(WorkerFrame::WriteFile {
                        id,
                        path: path.clone(),
                        data_b64: body(),
                    })
                    .await;
                assert!(
                    matches!(answer, ToolhostFrame::FileError { errno: 30, .. }),
                    "a write to {path}: {answer:?}"
                );
            }
            let id = launched.toolhost.id();
            let answer = launched
                .toolhost
                .ask(WorkerFrame::RemoveFile {
                    id,
                    path: "/.kata/kata-toolhost".to_owned(),
                })
                .await;
            assert!(
                matches!(answer, ToolhostFrame::FileError { errno: 30, .. }),
                "removing the toolhost: {answer:?}"
            );
            launched.toolhost.exec(1, "touch /.kata/x").await;
            let (_, stderr, code, _) = launched.toolhost.drain(1).await;
            assert!(
                code != Some(0) && stderr.contains("Read-only file system"),
                "touch /.kata/x: code {code:?}, stderr {stderr}"
            );
            let id = launched.toolhost.id();
            let answer = launched
                .toolhost
                .ask(WorkerFrame::WriteFile {
                    id,
                    path: "/work/landed".to_owned(),
                    data_b64: body(),
                })
                .await;
            assert_eq!(answer, ToolhostFrame::Done { id });
            assert_eq!(
                std::fs::read(launched.placed.attempt_root.join("work/landed"))
                    .expect("the host's copy"),
                b"planted"
            );
            launched.toolhost.close_stdin();
            assert!(launched.finish().await.success());
        },
    );
}

/// **`KillAll` leaves only the toolhost in the capsule's cgroup, and `Shutdown` leaves
/// nothing.** Three sleeps run: one a live session, one in a NEW session (`setsid`),
/// one orphaned by a double fork. After `KillAll`'s `Done`, the container's
/// `cgroup.procs` lists exactly the init within 10 s; after `Shutdown`'s `Bye` and the
/// init's exit 0 it lists nothing, before the teardown; and the teardown removes the
/// kata-owned cgroup directory.
///
/// **Would red if:** `KillAll` reached only each session's process group (the `setsid`
/// sleep survives in the cgroup), or `Shutdown` did not end the init (the cgroup still
/// lists it at the read before the teardown). `Shutdown`'s own kill has nothing left
/// to kill here, `KillAll` having run first; host-free,
/// `shutdown_kills_reaps_says_bye_and_exits_zero` (`bin/kata-toolhost/tests/
/// toolhost.rs`) guards it.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn close_leaves_no_task_in_the_cgroup() {
    delegated("close_leaves_no_task_in_the_cgroup", async {
        let rig = Rig::new();
        let mut launched = rig.launch("toolhost-close").await;
        launched.toolhost.admit().await;
        launched.toolhost.exec(1, "exec sleep 300").await;
        launched
            .toolhost
            .exec(
                2,
                "setsid sh -c 'exec sleep 300' </dev/null >/dev/null 2>&1 & \
                 (sleep 300 </dev/null >/dev/null 2>&1 &); true",
            )
            .await;
        assert_eq!(launched.toolhost.drain(2).await.2, Some(0));
        let init = launched.init_pid();
        let cgroup = launched.cgroup();
        eventually(
            Duration::from_secs(10),
            "the cgroup lists the init and three sleeps",
            || cgroup_tasks(&cgroup),
            |tasks| tasks.len() == 4,
        )
        .await;
        let id = launched.toolhost.id();
        launched.toolhost.send(&WorkerFrame::KillAll { id }).await;
        let mut frames = Vec::new();
        loop {
            let frame = launched.toolhost.next().await.expect("KillAll's answer");
            let done = frame == ToolhostFrame::Done { id };
            frames.push(frame);
            if done {
                break;
            }
        }
        assert!(
            frames.contains(&ToolhostFrame::Exited {
                session: SessionId(1),
                code: None,
                signal: Some(9),
            }),
            "{frames:?}"
        );
        eventually(
            Duration::from_secs(10),
            "only the toolhost is left in the cgroup",
            || cgroup_tasks(&cgroup),
            |tasks| tasks.as_slice() == [init],
        )
        .await;
        let id = launched.toolhost.id();
        let answer = launched.toolhost.ask(WorkerFrame::Shutdown { id }).await;
        assert_eq!(answer, ToolhostFrame::Bye { id, reaped: 0 });
        assert_eq!(
            launched.toolhost.next().await,
            None,
            "stdout closes after the Bye"
        );
        eventually(
            Duration::from_secs(10),
            "the cgroup is empty before the teardown",
            || cgroup_tasks(&cgroup),
            Vec::is_empty,
        )
        .await;
        let exit = launched.finish().await;
        assert!(exit.success(), "{exit}");
        assert!(
            !cgroup.exists(),
            "the kata-owned cgroup survived the teardown"
        );
    });
}

/// **The end of the worker ends the init, and with it every session: the cgroup is
/// empty within 10 s, before any teardown.** With a live session and a background
/// sleep running, the worker's stdin closes (a worker that died); the container's
/// `cgroup.procs` empties and the init exits 0 — before the runtime's sweep, which has
/// not run yet.
///
/// What empties the cgroup here is the init's EXIT: the kernel kills every process of
/// a pid namespace whose init exits, so this cell holds whether or not the toolhost
/// killed its children first (measured: with the stdin-EOF `KillAll` removed it stays
/// green, slower by the 5 s flush grace). The toolhost's own stdin-EOF kill is guarded
/// host-free, outside any namespace, by `the_end_of_stdin_kills_every_session_and_
/// exits_zero` (`bin/kata-toolhost/tests/toolhost.rs`).
///
/// **Would red if:** stdin EOF did not end the init (the cgroup keeps it and the
/// sleeps until the sweep), or the init's exit were not 0.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_worker_eof_kills_every_session() {
    delegated("a_worker_eof_kills_every_session", async {
        let rig = Rig::new();
        let mut launched = rig.launch("toolhost-eof").await;
        launched.toolhost.admit().await;
        launched
            .toolhost
            .exec(
                1,
                "sleep 300 </dev/null >/dev/null 2>&1 & echo ready; exec sleep 300",
            )
            .await;
        launched.toolhost.output_until(1, "ready").await;
        let cgroup = launched.cgroup();
        eventually(
            Duration::from_secs(10),
            "the cgroup lists the init and two sleeps",
            || cgroup_tasks(&cgroup),
            |tasks| tasks.len() == 3,
        )
        .await;
        launched.toolhost.close_stdin();
        eventually(
            Duration::from_secs(10),
            "the cgroup is empty after the worker's end",
            || cgroup_tasks(&cgroup),
            Vec::is_empty,
        )
        .await;
        let exit = launched.finish().await;
        assert!(exit.success(), "{exit}");
    });
}

/// **A stand-in init's `Hello` is classified `toolhost_mismatch` inside a real
/// capsule.** The provider entry's `toolhost/kata-toolhost` is a STAND-IN init: a
/// busybox script that writes a `Hello` of this protocol with an all-zero digest, then
/// records every byte it receives to `/work/received`. Its `Hello` crosses the real
/// bundle, the real `/.kata` bind and the worker's live FIFOs, and `Hello::check`
/// refuses it as `toolhost_mismatch` (source digest).
///
/// What this cell does NOT prove: that the worker refuses before any tool frame. The
/// double here is this file's, and it chooses to send nothing after the `Hello`; the
/// stand-in's empty record shows only that the rig delivered nothing of its own. The
/// refusal's timing belongs to the worker's toolhost client, which reads the `Hello`
/// before its first frame: to that client's host-free cell, and, over this same
/// stand-in in a real capsule, to `nanocode_capsule_live`'s handshake cells.
///
/// **Would red if:** `Hello::check` passed an all-zero source digest, or the bundle
/// did not exec the provider entry's `toolhost/kata-toolhost` as the init (no `Hello`
/// would arrive).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_stand_in_hello_is_a_toolhost_mismatch_in_a_real_capsule() {
    delegated(
        "a_stand_in_hello_is_a_toolhost_mismatch_in_a_real_capsule",
        async {
            let scratch = tempfile::tempdir().expect("a scratch directory");
            let stand_in = stand_in_toolhost(scratch.path());
            let rig = Rig::with_toolhost(&stand_in);
            let mut launched = rig.launch("toolhost-mismatch").await;
            let hello = launched.toolhost.hello().await;
            assert!(
                matches!(hello.check(), Err(ToolhostMismatch::SourceDigest { .. })),
                "the stand-in's Hello is refused by its source digest: {hello:?}"
            );
            launched.toolhost.close_stdin();
            let received = launched.placed.attempt_root.join("work/received");
            let exit =
                tokio::time::timeout(Duration::from_secs(30), launched.placed.process.wait())
                    .await
                    .expect("the stand-in exits on stdin EOF")
                    .expect("the terminal frame decodes");
            assert!(
                exit.success(),
                "{exit}; stderr {}",
                launched.placed.stderr()
            );
            assert_eq!(
                std::fs::read(&received).expect("the stand-in's record"),
                b"",
                "the rig itself sent the stand-in bytes"
            );
            let teardown = kata_worker::interactive_capsule::InteractiveTeardown::teardown(
                launched.placed.placement,
            )
            .await;
            assert!(teardown.is_confirmed(), "{teardown:?}");
        },
    );
}

/// **A signal sent from inside the capsule does not end the toolhost, which catches
/// only SIGCHLD.** The init's `SigCgt`, read from the host's `/proc`, is exactly
/// SIGCHLD's bit. A session sends PID 1 SIGTERM, SIGINT, SIGHUP, SIGSEGV, SIGBUS and
/// SIGKILL and exits 0; the init is still PID 1 on the host's `/proc`, and a further
/// `Exec` still answers.
///
/// **Would red if:** the toolhost kept std's SIGSEGV or SIGBUS handler or installed any
/// handler but SIGCHLD's (`SigCgt` holds its bit; the kernel would deliver that
/// signal), or were not its pid namespace's init (SIGKILL would end it).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_signal_from_inside_the_capsule_does_not_end_the_toolhost() {
    delegated(
        "a_signal_from_inside_the_capsule_does_not_end_the_toolhost",
        async {
            let rig = Rig::new();
            let mut launched = rig.launch("toolhost-signal").await;
            launched.toolhost.admit().await;
            let init = launched.init_pid();
            let status = std::fs::read_to_string(format!("/proc/{init}/status"))
                .expect("the init's status on the host");
            let caught = status
                .lines()
                .find_map(|line| line.strip_prefix("SigCgt:"))
                .map(|mask| u64::from_str_radix(mask.trim(), 16).expect("a hex mask"))
                .expect("a SigCgt line");
            assert_eq!(caught, 1 << (17 - 1), "the init's SigCgt is {caught:016x}");
            launched
                .toolhost
                .exec(
                    1,
                    "kill -TERM 1; kill -INT 1; kill -HUP 1; kill -SEGV 1; kill -BUS 1; \
                     kill -KILL 1; echo sent",
                )
                .await;
            let (stdout, stderr, code, _) = launched.toolhost.drain(1).await;
            assert_eq!((stdout.as_str(), code), ("sent\n", Some(0)), "{stderr}");
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(
                namespace_pid(init),
                Some(1),
                "the init is gone after the signals"
            );
            launched.toolhost.exec(2, "echo still").await;
            assert_eq!(launched.toolhost.drain(2).await.0, "still\n");
            launched.toolhost.close_stdin();
            assert!(launched.finish().await.success());
        },
    );
}

/// **A capsule process cannot open the toolhost's descriptors or read its memory.**
/// From a session: opening `/proc/1/fd/0` (the worker's FIFO end), resolving it with
/// `readlink`, and reading `/proc/1/environ` and `/proc/1/mem` each fail, the three
/// opens "Permission denied", read from the session's own stderr and exit codes.
///
/// MEASURED, and stated rather than claimed away: LISTING `/proc/1/fd` succeeds
/// inside the capsule. A non-dumpable task's `/proc` entries are owned by its user
/// namespace's root, which every capsule process is, so the directory's mode admits
/// them; what the dumpable bit gates is the ptrace check every open, `readlink`,
/// `environ` and `mem` read goes through. So a capsule process can count the
/// toolhost's descriptors and can use none of them.
///
/// **Would red if:** the toolhost were dumpable (a same-uid process could open the
/// worker's FIFO ends, inject frames, or forge an `Exited` or a `Bye`).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_capsule_process_cannot_open_the_toolhost_descriptors() {
    delegated(
        "a_capsule_process_cannot_open_the_toolhost_descriptors",
        async {
            let rig = Rig::new();
            let mut launched = rig.launch("toolhost-fds").await;
            launched.toolhost.admit().await;
            launched
                .toolhost
                .exec(
                    1,
                    "(exec 3</proc/1/fd/0); echo open=$?; readlink /proc/1/fd/0; echo link=$?; \
                 cat /proc/1/environ >/dev/null; echo environ=$?; \
                 cat /proc/1/mem </dev/null >/dev/null; echo mem=$?",
                )
                .await;
            let (stdout, stderr, code, _) = launched.toolhost.drain(1).await;
            assert_eq!(code, Some(0), "{stdout} / {stderr}");
            for probe in ["open", "link", "environ", "mem"] {
                assert!(
                    stdout.contains(&format!("{probe}="))
                        && !stdout.contains(&format!("{probe}=0")),
                    "{probe} succeeded: {stdout} / {stderr}"
                );
            }
            assert!(
                !stdout.contains("pipe:"),
                "readlink resolved a descriptor: {stdout}"
            );
            for denied in ["/proc/1/fd/0", "/proc/1/environ", "/proc/1/mem"] {
                assert!(
                    stderr
                        .lines()
                        .any(|line| line.contains(denied) && line.contains("Permission denied")),
                    "{denied} is not refused EACCES: {stderr}"
                );
            }
            launched.toolhost.close_stdin();
            assert!(launched.finish().await.success());
        },
    );
}
