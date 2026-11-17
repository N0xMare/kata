//! Dedicated kata worker daemon entry point.
//!
//! This subordinate-capacity process connects to the installed main and runs
//! the recv/execute/send loop. It owns no workflow authority.
//!
//! Subcommands:
//! - `kata-worker run --config <path>` — start the daemon.
//! - `kata-worker provision --main unix://<socket> --secret-file <path>` — write a
//!   `WorkerNodeConfig` + credential file.
//! - `kata-worker version` — print the binary version.

// The workspace `deny(unsafe_code)` applies, and NOT a crate-level
// `#![forbid(unsafe_code)]`: `forbid` cannot be relaxed below it (E0453), and
// putting back a launch value `.env` replaced writes the process environment,
// which is `unsafe`. `restore_launch_values` is the one item carrying
// `#[allow(unsafe_code)]`, with its SAFETY argument.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kata_types::identity::WorkerResource;
use kata_types::operator_dotenv_enabled;

// `pidfile` lives in the `kata_worker_bin` library crate
// (`src/lib.rs`) so integration tests under `tests/` can reach it;
// binaries themselves are not testable from `tests/`. Importing
// via the library keeps the binary entry point and the test
// surface in sync — there is no second copy of the module here.
use kata_worker_bin::pidfile::PidFile;

#[derive(Debug, Parser)]
#[command(name = "kata-worker", version, about = "Dedicated kata worker daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the worker daemon and connect to the configured main.
    Run {
        /// Path to the `WorkerNodeConfig` TOML file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Provision local-worker files for `kata-worker run`.
    Provision {
        /// Installed-main local socket (`unix:///path/to/socket`).
        #[arg(long)]
        main: String,
        /// Owner-only file containing the installed main's local enrollment
        /// secret. Raw secrets are never accepted through argv.
        #[arg(long)]
        secret_file: PathBuf,
        /// Output config path. Defaults to `~/.kata/worker.toml`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The installed main's data directory — its `operational.db`,
        /// `cas.db` and `cas/` planes. Required: the provisioned worker admits
        /// the `oci` capsule arm, whose route resolves a capsule's environment
        /// and input trees through the main's planes read-only
        /// (`worker_main_data_dir_undeclared` refuses a worker started
        /// without it).
        #[arg(long)]
        main_data_dir: PathBuf,
        /// Capability the provisioned worker should advertise. Repeat
        /// once per capability. The worker advertises exactly these, plus
        /// `agent:shell`, which every capsule worker serves. The main's
        /// worker inventory shows them; nothing is routed or gated on an
        /// `agent_backend=<label>`: capsule placement demands no agent
        /// label, and the agent a capsule runs is the main's
        /// `[agents.<label>]` declaration.
        ///
        /// Accepted forms (parsed by
        /// [`WorkerResource::from_str`]):
        ///
        /// - `shell`
        /// - `network`
        /// - `agent_backend=<label>`  (harness)
        /// - `disk=<u32>`
        /// - `gpu=<u32>`
        /// - `custom=<string>`
        #[arg(
            long = "capability",
            value_parser = WorkerResource::from_str,
            action = clap::ArgAction::Append,
        )]
        capability: Vec<WorkerResource>,
    },
    /// Print the binary version and exit.
    Version,
}

fn main() -> Result<()> {
    // Before anything reads the environment or opens a file: this daemon's Code
    // Mode interpreter process is this executable, re-executed.
    kata_code_mode_host::run_if_interpreter();
    // Load operator-local `.env` if present (in cwd or ancestors). No-op
    // when absent. Populates std::env before clap parses
    // `#[arg(env = ...)]` defaults and before any config file resolves
    // env-var interpolations. See `.env.example` for the surface.
    load_operator_dotenv();
    let cli = Cli::parse();
    match cli.command {
        Command::Run { config } => run_with_pidfile(config),
        Command::Provision {
            main,
            secret_file,
            out,
            main_data_dir,
            capability,
        } => {
            let secret = kata_worker::daemon::load_local_enrollment_secret(&secret_file)?;
            kata_worker::daemon::provision_worker(main, secret, out, capability, main_data_dir)
        }
        Command::Version => {
            println!("kata-worker {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

/// `.env` never overrides a launch value. dotenvy judges a variable present
/// with `std::env::var`, which errs on a value that is not UTF-8 as on an
/// unset one, so such a launch value is put back after the load: the daemon's
/// credential source refuses that key by name instead of lifting the file's.
fn load_operator_dotenv() {
    if operator_dotenv_enabled() {
        let undecodable: Vec<_> = std::env::vars_os()
            .filter(|(_, value)| value.to_str().is_none())
            .collect();
        let _ = dotenvy::dotenv();
        restore_launch_values(undecodable);
    }
}

/// Put back each launch value `.env` replaced — only a value that is not UTF-8
/// can be, since dotenvy leaves every variable `std::env::var` reads.
#[allow(unsafe_code)]
fn restore_launch_values(launch: Vec<(std::ffi::OsString, std::ffi::OsString)>) {
    for (name, value) in launch {
        if std::env::var_os(&name).as_ref() != Some(&value) {
            // SAFETY: `load_operator_dotenv` runs first in `main`, before any
            // thread exists, so nothing reads or writes the environment
            // concurrently — the same boundary dotenvy's own `set_var` relies on.
            unsafe { std::env::set_var(&name, &value) };
        }
    }
}

/// Wrap `run_worker_daemon` with a pidfile guard: a second `kata-worker`
/// against the same pid directory is refused while the first is live, and
/// the file is removed when the worker exits.
///
/// Pidfile path is `<pid_dir>/kata-worker.pid`, where `pid_dir` is:
///   1. `$KATA_DATA_DIR` if set, else
///   2. `$HOME/.kata/data`, else
///   3. the current working directory.
///
/// It is resolved from the environment rather than the worker config so the
/// guard is taken before the config is read.
fn run_with_pidfile(config: PathBuf) -> Result<()> {
    let pid_dir = resolve_pid_dir();
    let _pidfile = PidFile::write(&pid_dir, "kata-worker").with_context(|| {
        format!(
            "failed to write kata-worker pidfile in {}",
            pid_dir.display()
        )
    })?;
    // Drop order: the pidfile guard is dropped after `run_worker_daemon`
    // returns, whether that's a clean exit, a panic, or a signal-
    // triggered shutdown (the daemon installs SIGTERM + SIGINT handlers
    // internally — see `kata_worker::daemon::worker_run_loop`).
    kata_worker::daemon::run_worker_daemon(
        config,
        kata_worker::owner_home::KataLoginsDir::resolve(),
    )
}

fn resolve_pid_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KATA_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home).join(".kata").join("data");
    }
    PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_dotenv_presence_suppresses_ancestor_injection() {
        const CHILD: &str = "KATA_WORKER_DOTENV_TEST_CHILD";
        const EXPECT_LOAD: &str = "KATA_WORKER_DOTENV_TEST_EXPECT_LOAD";
        const AMBIENT: &str = "KATA_WORKER_DOTENV_REGRESSION";

        if std::env::var_os(CHILD).is_some() {
            load_operator_dotenv();
            let expected = std::env::var_os(EXPECT_LOAD).as_deref() == Some("yes".as_ref());
            assert_eq!(
                std::env::var_os(AMBIENT).is_some(),
                expected,
                "kata-worker dotenv load decision diverged"
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".env"), format!("{AMBIENT}=drifted\n")).unwrap();
        let descendant = root.path().join("nested/descendant");
        std::fs::create_dir_all(&descendant).unwrap();
        for disabled in [false, true] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("tests::no_dotenv_presence_suppresses_ancestor_injection")
                .arg("--nocapture")
                .current_dir(&descendant)
                .env_clear()
                .env(CHILD, "1")
                .env(EXPECT_LOAD, if disabled { "no" } else { "yes" });
            if disabled {
                command.env(kata_types::KATA_NO_DOTENV, "");
            }
            let output = command.output().expect("run kata-worker dotenv child");
            assert!(
                output.status.success(),
                "kata-worker dotenv child failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// **`.env` never overrides a launch value that is not UTF-8.** dotenvy
    /// judges presence with `std::env::var`, which errs on such a value as on
    /// an unset one; the daemon's credential source would then lift the file's
    /// key instead of refusing the launch one. After the load the launch bytes
    /// are still the variable's, and a second `.env` variable loaded.
    ///
    /// **Would red if:** the load left presence to dotenvy's check alone.
    #[test]
    fn dotenv_never_overrides_a_launch_value_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt as _;
        const CHILD: &str = "KATA_WORKER_LAUNCH_UTF8_TEST_CHILD";
        const KEY: &str = "KATA_WORKER_LAUNCH_UTF8_TEST_KEY";
        const LOADED: &str = "KATA_WORKER_LAUNCH_UTF8_TEST_LOADED";
        const LAUNCH_VALUE: &[u8] = b"sk-launch\xff";

        if std::env::var_os(CHILD).is_some() {
            load_operator_dotenv();
            assert_eq!(
                std::env::var_os(KEY)
                    .as_deref()
                    .map(std::ffi::OsStr::as_bytes),
                Some(LAUNCH_VALUE),
                "the launch value, not `.env`'s"
            );
            assert_eq!(std::env::var(LOADED).as_deref(), Ok("file"));
            return;
        }

        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".env"),
            format!("{KEY}=file\n{LOADED}=file\n"),
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::dotenv_never_overrides_a_launch_value_that_is_not_utf8")
            .arg("--nocapture")
            .current_dir(root.path())
            .env_clear()
            .env(CHILD, "1")
            .env(KEY, std::ffi::OsStr::from_bytes(LAUNCH_VALUE))
            .output()
            .expect("run kata-worker launch-utf8 child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "kata-worker launch-utf8 child failed: stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn provision_cli_exposes_main_local_socket_not_home_endpoint() {
        Cli::try_parse_from([
            "kata-worker",
            "provision",
            "--main",
            "unix:///tmp/kata-worker.sock",
            "--secret-file",
            "/tmp/local-worker.secret",
            "--main-data-dir",
            "/tmp/kata-main-data",
        ])
        .expect("--main local-socket form must parse");

        let error = Cli::try_parse_from([
            "kata-worker",
            "provision",
            "--home",
            "ws://127.0.0.1:8410",
            "--secret-file",
            "/tmp/local-worker.secret",
            "--main-data-dir",
            "/tmp/kata-main-data",
        ])
        .expect_err("the removed --home network surface must not parse");
        let rendered = error.to_string();
        assert!(rendered.contains("--main"), "diagnostic={rendered}");
        assert!(!rendered.contains("ws://host"), "diagnostic={rendered}");
    }

    #[test]
    fn provision_cli_rejects_raw_secret_argv() {
        let error = Cli::try_parse_from([
            "kata-worker",
            "provision",
            "--main",
            "unix:///tmp/kata-worker.sock",
            "--secret",
            "must-not-appear-in-argv",
            "--main-data-dir",
            "/tmp/kata-main-data",
        ])
        .expect_err("raw argv secret surface must stay removed");
        assert!(error.to_string().contains("--secret-file"));
    }

    #[test]
    fn provision_cli_requires_main_data_dir() {
        // The provisioned worker admits the `oci` capsule arm, whose route
        // resolves the main's planes through the main's data directory — an
        // omitted `--main-data-dir` would emit a config the daemon refuses at
        // start (`worker_main_data_dir_undeclared`), so clap refuses it at
        // provision instead.
        let error = Cli::try_parse_from([
            "kata-worker",
            "provision",
            "--main",
            "unix:///tmp/kata-worker.sock",
            "--secret-file",
            "/tmp/local-worker.secret",
        ])
        .expect_err("a worker provisioned without --main-data-dir must not parse");
        assert!(
            error.to_string().contains("--main-data-dir"),
            "diagnostic={error}"
        );
    }
}
