//! Bounded synchronous subprocesses at the main's VCS boundary.
//!
//! The deadline covers pipe transfer and child completion after spawn. On error
//! the process group receives SIGKILL and a background waiter reaps the direct
//! child, so an uninterruptible kernel wait cannot block the main's caller.
//! This is lifecycle control, not containment: descendants that create a new
//! session can escape the group. A timed-out mutation has unknown outcome.

use std::io;
use std::process::{Command, Output};
use std::time::Duration;

use kata_types::KataError;

/// Hang detection for local git operations, not an acceptance latency target.
pub const LOCAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct UnknownCommandOutcome(io::Error);

impl std::fmt::Display for UnknownCommandOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "VCS subprocess started but its outcome is unknown: {}; inspect state before retrying",
            self.0
        )
    }
}

impl std::error::Error for UnknownCommandOutcome {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A post-spawn failure is not evidence that the mutation did not happen.
pub fn command_outcome_unknown(error: &io::Error) -> bool {
    match error.get_ref() {
        Some(source) => source.is::<UnknownCommandOutcome>(),
        None => false,
    }
}

/// The typed error a forge command (`git push`, `git ls-remote`, a `gh` verb)
/// that did not run to an exit status is, `what` naming the command. One
/// classification for every forge door: a failure after the spawn is
/// `OutcomeUnknown` (the command may have acted), the deadline `Timeout`, a
/// program that is not there `Config` (`not_found` is the operator's fix), and
/// any other spawn fault `Internal`, never a false "not found".
pub(crate) fn forge_command_error(what: &str, not_found: &str, error: &io::Error) -> KataError {
    match error.kind() {
        io::ErrorKind::TimedOut => KataError::Timeout(format!("forge_export: {what}: {error}")),
        _ if command_outcome_unknown(error) => {
            KataError::OutcomeUnknown(format!("forge_export: {what}: {error}"))
        }
        io::ErrorKind::NotFound => KataError::Config(format!("forge_export: {not_found}")),
        _ => KataError::Internal(format!("forge_export: failed to spawn {what}: {error}")),
    }
}

/// The most bytes of a failed forge command's stderr a refusal quotes.
pub(crate) const MAX_QUOTED_STDERR_BYTES: usize = 1024;

/// `stderr`, trimmed and cut at a character boundary to at most
/// [`MAX_QUOTED_STDERR_BYTES`]: the part of it a refusal quotes.
pub(crate) fn quoted_stderr(stderr: &[u8]) -> String {
    let mut quoted = String::from_utf8_lossy(stderr).trim().to_owned();
    if quoted.len() > MAX_QUOTED_STDERR_BYTES {
        let mut cut = MAX_QUOTED_STDERR_BYTES;
        while !quoted.is_char_boundary(cut) {
            cut -= 1;
        }
        quoted.truncate(cut);
    }
    quoted
}

/// The typed error a forge command that exited unsuccessfully is: `Network`,
/// quoting its exit status and a bounded part of its stderr
/// ([`quoted_stderr`]). It never says the remote is untouched; the caller's
/// observer says that.
pub(crate) fn forge_exit_error(what: &str, output: &Output) -> KataError {
    let code = output
        .status
        .code()
        .map_or_else(|| "signal".to_owned(), |code| code.to_string());
    KataError::Network(format!(
        "forge_export: {what} failed (exit {code}): {}",
        quoted_stderr(&output.stderr)
    ))
}

/// A VCS command carries its override set and deadline from construction.
/// No raw Command escapes, so a caller cannot accidentally use its unbounded wait.
pub struct VcsCommand {
    command: Command,
    timeout: Duration,
}

impl VcsCommand {
    pub fn new(
        program: impl AsRef<std::ffi::OsStr>,
        overrides: &[(&str, &str)],
        timeout: Duration,
    ) -> Self {
        let mut command = Command::new(program);
        for (key, value) in overrides {
            command.arg("-c").arg(format!("{key}={value}"));
        }
        Self { command, timeout }
    }
    pub fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.command.arg(arg);
        self
    }
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.command.args(args);
        self
    }
    pub fn current_dir(&mut self, path: impl AsRef<std::path::Path>) -> &mut Self {
        self.command.current_dir(path);
        self
    }
    pub fn env(
        &mut self,
        key: impl AsRef<std::ffi::OsStr>,
        value: impl AsRef<std::ffi::OsStr>,
    ) -> &mut Self {
        self.command.env(key, value);
        self
    }
    pub fn env_remove(&mut self, key: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.command.env_remove(key);
        self
    }
    pub fn output(&mut self) -> io::Result<Output> {
        self.output_with_input(&[])
    }
    pub fn output_with_input(&mut self, input: &[u8]) -> io::Result<Output> {
        self.output_with_guard(input, usize::MAX, &mut || Ok(()))
    }
    /// Bound captured output and inspect caller-owned resources during the pump.
    /// The guard is a cancellation threshold, not kernel resource containment.
    pub fn output_with_guard(
        &mut self,
        input: &[u8],
        max_output_bytes: usize,
        guard: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Output> {
        capture(
            &mut self.command,
            input,
            self.timeout,
            OutputCap::Together(max_output_bytes),
            guard,
        )
    }

    /// Run with no input, stdout capped at `max_stdout_bytes` (past it the
    /// command is killed, a `FileTooLarge` error) and stderr drained to the
    /// end but only its first `kept_stderr_bytes` kept: a command's answer is
    /// its stdout, and however much it prints on stderr is no answer.
    pub(crate) fn output_capping_stdout(
        &mut self,
        max_stdout_bytes: usize,
        kept_stderr_bytes: usize,
    ) -> io::Result<Output> {
        capture(
            &mut self.command,
            &[],
            self.timeout,
            OutputCap::Stdout {
                max_stdout_bytes,
                kept_stderr_bytes,
            },
            &mut || Ok(()),
        )
    }
}

/// How [`capture`] bounds what a command prints.
#[derive(Clone, Copy)]
enum OutputCap {
    /// Stdout and stderr together; past it the command is killed.
    Together(usize),
    /// Stdout alone; past it the command is killed. Stderr past
    /// `kept_stderr_bytes` is read and dropped.
    Stdout {
        max_stdout_bytes: usize,
        kept_stderr_bytes: usize,
    },
}

/// What one pipe may still take: bytes past a `Fail` budget are a
/// `FileTooLarge` error, bytes past a `Keep` budget are dropped.
enum PipeBudget {
    Fail(usize),
    Keep(usize),
}

#[cfg(not(unix))]
fn capture(
    _command: &mut Command,
    _input: &[u8],
    _timeout: Duration,
    _cap: OutputCap,
    _guard: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Output> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded VCS subprocesses require Unix process groups",
    ))
}

#[cfg(unix)]
fn capture(
    command: &mut Command,
    mut input: &[u8],
    timeout: Duration,
    cap: OutputCap,
    resource_guard: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Output> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Stdio};
    use std::time::Instant;

    // Own the child through every fallible pipe setup/read/write. Killing only
    // the direct child leaves git's SSH/credential helpers holding the pipes.
    struct ChildGuard(Option<Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                if let Ok(pid) = i32::try_from(child.id()) {
                    let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
                }
                let _ = child.kill();
                // Reap off the calling thread: an uninterruptible kernel wait
                // must not turn the timeout's cleanup into another unbounded wait.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }
    }
    fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
        let flags = fcntl(pipe.as_raw_fd(), FcntlArg::F_GETFL)?;
        fcntl(
            pipe.as_raw_fd(),
            FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
        )?;
        Ok(())
    }
    fn drain(
        pipe: &mut impl Read,
        bytes: &mut Vec<u8>,
        eof: &mut bool,
        budget: &mut PipeBudget,
    ) -> io::Result<bool> {
        let mut active = false;
        let mut buf = [0; 8192];
        // Bound each drain so a continuously-writing child cannot monopolize
        // the loop and prevent the deadline or the other pipe being checked.
        for _ in 0..16 {
            match pipe.read(&mut buf) {
                Ok(0) => {
                    *eof = true;
                    break;
                }
                Ok(n) => {
                    match budget {
                        PipeBudget::Fail(left) => {
                            *left = left
                                .checked_sub(n)
                                .ok_or_else(|| io::Error::from(io::ErrorKind::FileTooLarge))?;
                            bytes.extend_from_slice(&buf[..n]);
                        }
                        PipeBudget::Keep(left) => {
                            let kept = n.min(*left);
                            bytes.extend_from_slice(&buf[..kept]);
                            *left -= kept;
                        }
                    }
                    active = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(active)
    }

    let started = Instant::now();
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guard = ChildGuard(Some(command.spawn()?));
    let result = (|| {
        let child = guard
            .0
            .as_mut()
            .expect("child guard owns the spawned child");
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take().expect("stdout was piped");
        let mut stderr = child.stderr.take().expect("stderr was piped");
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        if let Some(pipe) = &stdin {
            nonblocking(pipe)?;
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (mut out_eof, mut err_eof) = (false, false);
        let mut status = None;
        // Together, both pipes draw on `output_budget`; capping stdout
        // alone, stderr draws on its own keep budget.
        let (mut output_budget, mut stderr_budget) = match cap {
            OutputCap::Together(max) => (PipeBudget::Fail(max), None),
            OutputCap::Stdout {
                max_stdout_bytes,
                kept_stderr_bytes,
            } => (
                PipeBudget::Fail(max_stdout_bytes),
                Some(PipeBudget::Keep(kept_stderr_bytes)),
            ),
        };
        loop {
            resource_guard()?;
            if started.elapsed() >= timeout {
                // Some callers are deliberately best-effort cleanup. Their ignored
                // Result must not make a timed-out command disappear from the record.
                tracing::warn!(
                    timeout_ms = timeout.as_millis(),
                    "VCS subprocess deadline expired; requesting process-group termination; mutation outcome unknown"
                );
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "VCS subprocess exceeded {}ms; process-group termination requested; mutation outcome is unknown, inspect state before retrying",
                        timeout.as_millis()
                    ),
                ));
            }
            let mut active = drain(&mut stdout, &mut out, &mut out_eof, &mut output_budget)?;
            active |= drain(
                &mut stderr,
                &mut err,
                &mut err_eof,
                stderr_budget.as_mut().unwrap_or(&mut output_budget),
            )?;
            if input.is_empty() {
                stdin.take();
            }
            if let Some(pipe) = &mut stdin {
                match pipe.write(&input[..input.len().min(8192)]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "VCS subprocess stdin stopped accepting input",
                        ));
                    }
                    Ok(n) => {
                        input = &input[n..];
                        active = true;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            if status.is_none() {
                status = guard.0.as_mut().expect("child is owned").try_wait()?;
            }
            if let Some(status) = status
                && out_eof
                && err_eof
            {
                if !input.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "VCS subprocess exited before its full input was written",
                    ));
                }
                guard.0.take(); // try_wait already reaped it.
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
            if !active {
                std::thread::sleep(
                    Duration::from_millis(2).min(timeout.saturating_sub(started.elapsed())),
                );
            }
        }
    })();
    result.map_err(|error: io::Error| io::Error::new(error.kind(), UnknownCommandOutcome(error)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn recovery_output_limit_refuses_excess_bytes() {
        let result = VcsCommand::new("sh", &[], Duration::from_secs(5))
            .args(["-c", "printf 123456789"])
            .output_with_guard(&[], 8, &mut || Ok(()));
        assert!(
            result.is_err(),
            "nine bytes must not pass an eight-byte output budget"
        );
    }

    #[test]
    fn a_subprocess_deadline_refuses_a_hung_command() {
        let error = VcsCommand::new("sh", &[], Duration::from_millis(20))
            .args(["-c", "sleep 0.2"])
            .output()
            .expect_err("the deadline must terminate a command still running");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn duplex_pipes_preserve_input_output_and_nonzero_status() {
        let input = vec![b'x'; 512 * 1024];
        let output = VcsCommand::new("sh", &[], Duration::from_secs(10))
            .args(["-c", "head -c 262144 /dev/zero >&2; cat; exit 7"])
            .output_with_input(&input)
            .unwrap();
        assert_eq!(output.stdout, input);
        assert_eq!(output.stderr, vec![0; 262_144]);
        assert_eq!(output.status.code(), Some(7));
    }

    #[test]
    fn a_child_that_never_reads_stdin_is_bounded() {
        let error = VcsCommand::new("sh", &[], Duration::from_millis(100))
            .args(["-c", "sleep 30"])
            .output_with_input(&vec![0; 512 * 1024])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_kills_pipe_holding_descendants_and_reaps_the_direct_child() {
        let temp = tempfile::tempdir().unwrap();
        let pids = temp.path().join("pids");
        // Readiness is separate from the 1 s deadline under test: the pump's guard
        // holds the first pass until the shell has published both pids, so a loaded
        // host's slow `sh` start-up cannot fire the deadline before the descendant
        // exists (the rename publishes both pids at once). The wait is generous
        // because it bounds only process start-up.
        let mut ready = false;
        let error = VcsCommand::new("sh", &[], Duration::from_secs(1))
            .args([
                "-c",
                "sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1.tmp\"; mv \"$1.tmp\" \"$1\"; wait",
                "probe",
            ])
            .arg(&pids)
            .output_with_guard(&[], usize::MAX, &mut || {
                let ready_deadline = std::time::Instant::now() + Duration::from_secs(60);
                while !ready {
                    ready = pids.exists();
                    assert!(
                        std::time::Instant::now() < ready_deadline,
                        "the probe shell never published its pids"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let pids = std::fs::read_to_string(pids).unwrap();
        let ids: Vec<_> = pids.split_whitespace().collect();
        assert_eq!(ids.len(), 2);
        // Generous on purpose: the kill is immediate but the reap runs on a
        // background thread a loaded host can delay; the property is that the group
        // dies, not how fast.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let parent_reaped = !std::path::Path::new(&format!("/proc/{}", ids[0])).exists();
            let descendant_dead =
                std::fs::read_to_string(format!("/proc/{}/stat", ids[1])).map_or(true, |stat| {
                    stat.rsplit_once(") ")
                        .is_some_and(|(_, rest)| rest.starts_with("Z "))
                });
            if parent_reaped && descendant_dead {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "subprocess group survived timeout: {pids}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn the_production_vcs_doors_use_the_bounded_helper() {
        for source in [
            include_str!("../../workflow/src/worktree_isolation.rs"),
            include_str!("jj/forge_export.rs"),
            include_str!("identity.rs"),
            include_str!("forge.rs"),
        ] {
            assert!(!source.contains("use std::process::Command"));
            assert!(!source.contains("std::process::Command::new("));
            assert!(!source.contains("= Command::new("));
            assert!(!source.contains(".wait_with_output()"));
            assert!(source.contains("VcsCommand::new("));
        }
    }

    #[test]
    fn production_git_refuses_ambient_behavior_but_inherits_identity_and_trunk() {
        use kata_types::git_policy::GIT_EXECUTION_OVERRIDES;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let hooks = root.path().join("hooks");
        std::fs::create_dir(&repo).unwrap();
        std::fs::create_dir(&hooks).unwrap();
        let hook = hooks.join("pre-commit");
        std::fs::write(&hook, "#!/bin/sh\nexit 42\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let excludes = root.path().join("excludes");
        std::fs::write(&excludes, "ignored.txt\n").unwrap();
        let global = root.path().join("global");
        std::fs::write(&global, format!(
            "[user]\nname = Real Host\nemail = real@host.invalid\n[init]\ndefaultBranch = customer-trunk\n[core]\nhooksPath = {}\nautocrlf = true\nexcludesFile = {}\n[commit]\ngpgsign = true\n[tag]\ngpgsign = true\n[hook \"operator\"]\nevent = pre-commit\nevent = reference-transaction\ncommand = false\n",
            hooks.display(), excludes.display()
        )).unwrap();
        let run = |args: &[&str]| {
            let out = VcsCommand::new("git", GIT_EXECUTION_OVERRIDES, Duration::from_secs(10))
                .env("GIT_CONFIG_GLOBAL", &global)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        run(&["init", "-q"]);
        std::fs::write(repo.join("tracked.txt"), "line\r\n").unwrap();
        run(&["add", "tracked.txt"]);
        run(&["commit", "-qm", "bounded production commit"]);
        assert_eq!(run(&["show", "HEAD:tracked.txt"]), "line\r\n");
        assert_eq!(
            run(&["show", "-s", "--format=%an <%ae>"]),
            "Real Host <real@host.invalid>\n"
        );
        assert_eq!(
            run(&["symbolic-ref", "--short", "HEAD"]),
            "customer-trunk\n"
        );
        for (key, value) in GIT_EXECUTION_OVERRIDES {
            assert_eq!(run(&["config", "--get", key]).trim(), *value);
        }
        std::fs::write(repo.join("ignored.txt"), "must be visible\n").unwrap();
        assert!(run(&["status", "--porcelain"]).contains("ignored.txt"));
    }

    #[test]
    fn post_spawn_pipe_failure_is_unknown_but_a_missing_binary_is_not() {
        let error = VcsCommand::new("sh", &[], Duration::from_secs(5))
            .args(["-c", "exec 0<&-; sleep 30"])
            .output_with_input(&vec![0; 512 * 1024])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            command_outcome_unknown(&error),
            "a started process may already have mutated state"
        );
        let temp = tempfile::tempdir().unwrap();
        let missing = VcsCommand::new(temp.path().join("missing"), &[], Duration::from_secs(5))
            .output()
            .unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(!command_outcome_unknown(&missing));
    }
}
