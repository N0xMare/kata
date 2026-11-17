//! `kata login` / `kata logout`: kata's OWN login for its embedded agent
//! harness.
//!
//! Every file lives in the effective owner's logins directory
//! (`~/.config/kata/logins/`, the home resolved from the account record, never
//! `HOME`), the same directory every kata binary of this uid hands its worker.
//! The files and their checks are `kata_agent_nanocode::credential`'s; this
//! module is the operator's door to them. It never reads another tool's login.
//! `kata login status` contacts no issuer and refreshes nothing; `kata login
//! status --check` adds one authenticated, no-spend read per stored file
//! (`credential::check_login`).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{IsTerminal as _, Read as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use kata_agent_nanocode::credential::{
    self, DeviceCode, Issuer, LoginCheck, LoginFile, LoginProvider, LoginState,
};

use super::{LoginCmd, LoginProviderArg};

/// The longest API key `kata login --api-key` reads from stdin.
const MAX_API_KEY_BYTES: u64 = 4096;

/// `kata login <cmd>`.
///
/// # Errors
/// The login's own refusal, or a logins directory that cannot be resolved.
pub(super) fn run_login_cmd(cmd: LoginCmd) -> Result<()> {
    let dir = kata_worker::owner_home::kata_logins_dir()?;
    match cmd {
        LoginCmd::Openai { api_key: true, .. } => {
            store_key_from_stdin(&dir, LoginFile::OpenAiApiKey)
        }
        LoginCmd::Openai {
            api_key: false,
            device_code,
            browser,
            no_browser,
        } => {
            let flags = FlowFlags {
                device_code,
                browser,
                no_browser,
            };
            let (flow, why) = chatgpt_flow(flags, |name| std::env::var_os(name));
            println!(
                "kata logs in to ChatGPT with the {}: {why}.",
                flow.as_label()
            );
            match flow {
                ChatGptFlow::DeviceCode => login_chatgpt_device_code(&dir),
                ChatGptFlow::Browser { open_browser } => login_chatgpt_browser(&dir, open_browser),
            }
        }
        LoginCmd::Anthropic { api_key: _ } => {
            store_key_from_stdin(&dir, LoginFile::AnthropicApiKey)
        }
        LoginCmd::Status { check: false } => {
            print!("{}", render_status(&dir));
            Ok(())
        }
        LoginCmd::Status { check: true } => {
            print!("{}", render_status(&dir));
            let (report, verdict) = render_check(&dir, &credential::CheckHosts::default());
            print!("{report}");
            verdict
        }
    }
}

/// `kata logout <provider>`.
///
/// # Errors
/// A login file that exists and could not be removed.
pub(super) fn run_logout_cmd(provider: LoginProviderArg) -> Result<()> {
    let dir = kata_worker::owner_home::kata_logins_dir()?;
    let provider = match provider {
        LoginProviderArg::Openai => LoginProvider::Openai,
        LoginProviderArg::Anthropic => LoginProvider::Anthropic,
    };
    let removed = credential::logout(&dir, provider)?;
    if removed.is_empty() {
        println!(
            "kata holds no {} login in {}",
            provider.as_label(),
            dir.display()
        );
    }
    for file in removed.files {
        println!("removed {}", file.path(&dir).display());
    }
    for path in removed.crashed_copies {
        println!(
            "removed {} (left by a crashed write or login)",
            path.display()
        );
    }
    Ok(())
}

/// How `kata login openai` logs in to ChatGPT. Both flows store the same
/// `openai-chatgpt.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChatGptFlow {
    /// A URL and a one-time code the operator enters on any device; nothing
    /// listens on this host.
    DeviceCode,
    /// The browser (loopback) flow: a callback on localhost:1455 (or 1457);
    /// `open_browser` also asks the desktop to open the URL.
    Browser { open_browser: bool },
}

impl ChatGptFlow {
    const fn as_label(self) -> &'static str {
        match self {
            Self::DeviceCode => "device-code flow",
            Self::Browser { open_browser: true } => "browser flow",
            Self::Browser {
                open_browser: false,
            } => "browser flow, without opening a browser",
        }
    }
}

/// The flow flags of `kata login openai`. clap refuses any two of them
/// together, naming both.
#[derive(Clone, Copy, Debug, Default)]
struct FlowFlags {
    device_code: bool,
    browser: bool,
    no_browser: bool,
}

/// The flow `flags` choose, else the one the session's environment does
/// (`env` reads a variable; a set but empty one counts as unset): the
/// device-code flow for a remote session (`SSH_CONNECTION` or `SSH_TTY`) or one
/// with no graphical display (neither `DISPLAY` nor `WAYLAND_DISPLAY`), the
/// browser flow otherwise. Also why, for the operator.
fn chatgpt_flow(
    flags: FlowFlags,
    env: impl Fn(&str) -> Option<OsString>,
) -> (ChatGptFlow, &'static str) {
    if flags.device_code {
        return (ChatGptFlow::DeviceCode, "`--device-code` asked for it");
    }
    if flags.browser {
        return (
            ChatGptFlow::Browser { open_browser: true },
            "`--browser` asked for it",
        );
    }
    if flags.no_browser {
        return (
            ChatGptFlow::Browser {
                open_browser: false,
            },
            "`--no-browser` asked for it",
        );
    }
    let set = |name: &str| env(name).is_some_and(|value| !value.is_empty());
    if set("SSH_CONNECTION") || set("SSH_TTY") {
        return (
            ChatGptFlow::DeviceCode,
            "this session is remote (`SSH_CONNECTION` or `SSH_TTY` is set); `--browser` uses \
             the browser flow",
        );
    }
    if !set("DISPLAY") && !set("WAYLAND_DISPLAY") {
        return (
            ChatGptFlow::DeviceCode,
            "this session has no graphical display (neither `DISPLAY` nor `WAYLAND_DISPLAY` \
             is set); `--browser` uses the browser flow",
        );
    }
    (
        ChatGptFlow::Browser { open_browser: true },
        "this session is local with a display; `--device-code` uses the device-code flow",
    )
}

fn login_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the login's runtime")
}

fn login_chatgpt_browser(dir: &Path, open: bool) -> Result<()> {
    let account = login_runtime()?.block_on(credential::login_openai_chatgpt(dir, |url| {
        println!("Open this URL to log kata in to ChatGPT (it waits five minutes):\n\n  {url}\n");
        println!(
            "The callback is localhost:1455 (or 1457). On a remote host, forward it first \
             (ssh -L 1455:localhost:1455 <host>), or use `kata login openai --device-code`, \
             which needs no forward."
        );
        if open {
            open_browser(url);
        }
    }))?;
    print_logged_in(dir, &account);
    Ok(())
}

fn login_chatgpt_device_code(dir: &Path) -> Result<()> {
    let account = login_runtime()?.block_on(credential::login_openai_device_code(
        dir,
        &Issuer::default(),
        |code| print!("{}", device_code_prompt(code)),
        interrupted(),
    ))?;
    print_logged_in(dir, &account);
    Ok(())
}

/// Ctrl-C. Once this is first polled, SIGINT no longer kills the process: the
/// login refuses `device_code_interrupted` during the wait, and a SIGINT
/// after the approval lets the login finish storing. A handler that cannot be
/// installed interrupts nothing (Ctrl-C then kills the process, which has
/// stored nothing before the approval either).
async fn interrupted() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// What the operator is told to do with a device code. It holds the URL and
/// the one-time code only, never a token.
fn device_code_prompt(code: &DeviceCode) -> String {
    let expires = chrono::DateTime::from_timestamp_millis(code.expires_at_ms)
        .map_or_else(|| "at no stated time".to_owned(), |at| at.to_rfc3339());
    format!(
        "To log kata in to ChatGPT, open this page on any device and sign in:\n\n  {}\n\n\
         then enter this one-time code (it expires {expires}):\n\n  {}\n\n\
         Continue only if you started this login with `kata login openai`; if a website or \
         another person gave you this code, cancel. Waiting for the approval (Ctrl-C stores \
         nothing).\n",
        code.verification_url, code.user_code
    )
}

fn print_logged_in(dir: &Path, account: &credential::ChatGptAccount) {
    println!(
        "kata is logged in to ChatGPT (account {}); its login is {}",
        account.account_id,
        LoginFile::OpenAiChatGpt.path(dir).display()
    );
}

/// Ask the desktop to open `url`. Best effort: the URL is already printed, so
/// a host without `xdg-open` (or without a desktop) loses nothing.
fn open_browser(url: &str) {
    let _ = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Read one API key from stdin, never from the command line: the key would
/// otherwise land in shell history and in every process listing. A terminal is
/// refused, because it would echo the key.
fn store_key_from_stdin(dir: &Path, file: LoginFile) -> Result<()> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "`{}` reads the key from stdin, and stdin is a terminal that would echo it; pipe \
             it instead, e.g. `{} < key-file`",
            file.login_command(),
            file.login_command()
        );
    }
    let mut text = String::new();
    stdin
        .lock()
        .take(MAX_API_KEY_BYTES + 1)
        .read_to_string(&mut text)
        .context("reading the API key from stdin")?;
    if text.len() as u64 > MAX_API_KEY_BYTES {
        bail!("the API key on stdin is longer than {MAX_API_KEY_BYTES} bytes");
    }
    let key = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    credential::store_api_key(dir, file, key)?;
    println!("stored {}", file.path(dir).display());
    Ok(())
}

/// One line per login file, offline.
fn render_status(dir: &Path) -> String {
    let mut out = format!("kata logins in {}\n", dir.display());
    for file in LoginFile::ALL {
        let state = match credential::login_state(dir, file) {
            LoginState::Absent => format!("absent (`{}` writes it)", file.login_command()),
            LoginState::Insecure(reason) => format!("REFUSED, not owner-only: {reason}"),
            LoginState::Malformed(reason) => format!("REFUSED, unreadable: {reason}"),
            LoginState::ApiKey => "an API key is stored".to_owned(),
            LoginState::ChatGpt {
                account_id: None, ..
            } => "no completed ChatGPT login (run `kata login openai`)".to_owned(),
            LoginState::ChatGpt {
                account_id: Some(account),
                access_expires_at_ms,
                refresh_token,
                revision,
            } => format!(
                "ChatGPT login for account {account}; access token expires {}; refresh token \
                 {}; revision {revision}",
                access_expires_at_ms
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .map_or_else(|| "at no stated time".to_owned(), |at| at.to_rfc3339()),
                if refresh_token { "stored" } else { "ABSENT" },
            ),
        };
        let _ = writeln!(out, "  {}: {state}", file.file_name());
    }
    out
}

/// One line per login file: the verdict of [`credential::check_login`]; and
/// the command's exit, a refusal naming every stored file that did not check
/// `ok` (an absent file fails nothing).
fn render_check(dir: &Path, hosts: &credential::CheckHosts) -> (String, Result<()>) {
    let mut out = "checked (one authenticated read each, no spend):\n".to_owned();
    let mut failed = Vec::new();
    for file in LoginFile::ALL {
        let check = credential::check_login(dir, file, hosts);
        let detail = match &check {
            LoginCheck::Absent => "nothing stored, not checked".to_owned(),
            LoginCheck::Ok(detail)
            | LoginCheck::Refused(detail)
            | LoginCheck::Expired(detail)
            | LoginCheck::Unchecked(detail) => detail.clone(),
        };
        if !matches!(check, LoginCheck::Absent | LoginCheck::Ok(_)) {
            failed.push(file.file_name());
        }
        let _ = writeln!(out, "  {}: {}: {detail}", file.file_name(), check.label());
    }
    if failed.is_empty() {
        return (out, Ok(()));
    }
    let refusal = anyhow::anyhow!(
        "{} stored login(s) did not check `ok`: {}",
        failed.len(),
        failed.join(", ")
    );
    (out, Err(refusal))
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command};

    const DEVICE: ChatGptFlow = ChatGptFlow::DeviceCode;
    const BROWSER: ChatGptFlow = ChatGptFlow::Browser { open_browser: true };
    const PRINT_ONLY: ChatGptFlow = ChatGptFlow::Browser {
        open_browser: false,
    };

    fn flow(flags: FlowFlags, vars: &[(&str, &str)]) -> ChatGptFlow {
        chatgpt_flow(flags, |name| {
            vars.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| OsString::from(value))
        })
        .0
    }

    /// **The session picks the ChatGPT flow, and each flag overrides it.**
    /// With no flag: a session with `SSH_CONNECTION` or `SSH_TTY` set takes
    /// the device-code flow even with a display; one with neither and with
    /// `DISPLAY` or `WAYLAND_DISPLAY` set takes the browser flow, which opens
    /// a browser; one with no display takes the device-code flow; an empty
    /// variable counts as unset. Under every one of those environments,
    /// `--device-code` is the device-code flow, `--browser` the browser flow
    /// opening a browser, and `--no-browser` the browser flow printing the URL
    /// only.
    ///
    /// **Would red if:** a remote session with a display defaulted to the
    /// browser flow (the rule before the device-code flow), or a flag lost to
    /// the environment.
    #[test]
    fn the_session_picks_the_chatgpt_flow_and_each_flag_overrides_it() {
        let ssh = ("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22");
        let tty = ("SSH_TTY", "/dev/pts/3");
        let x11 = ("DISPLAY", ":0");
        let wayland = ("WAYLAND_DISPLAY", "wayland-0");
        let sessions: [(&[(&str, &str)], ChatGptFlow); 10] = [
            (&[], DEVICE),
            (&[x11], BROWSER),
            (&[wayland], BROWSER),
            (&[x11, wayland], BROWSER),
            (&[ssh], DEVICE),
            (&[tty], DEVICE),
            (&[x11, ssh], DEVICE),
            (&[wayland, tty], DEVICE),
            (&[("DISPLAY", ""), ("WAYLAND_DISPLAY", "")], DEVICE),
            (&[x11, ("SSH_CONNECTION", ""), ("SSH_TTY", "")], BROWSER),
        ];
        for (vars, expected) in sessions {
            assert_eq!(flow(FlowFlags::default(), vars), expected, "{vars:?}");
            for (flags, forced) in [
                (
                    FlowFlags {
                        device_code: true,
                        ..FlowFlags::default()
                    },
                    DEVICE,
                ),
                (
                    FlowFlags {
                        browser: true,
                        ..FlowFlags::default()
                    },
                    BROWSER,
                ),
                (
                    FlowFlags {
                        no_browser: true,
                        ..FlowFlags::default()
                    },
                    PRINT_ONLY,
                ),
            ] {
                assert_eq!(flow(flags, vars), forced, "{flags:?} {vars:?}");
            }
        }
    }

    /// **Contradictory `kata login openai` flags refuse, naming both.** Any
    /// two of `--device-code`, `--browser` and `--no-browser`, and `--api-key`
    /// with any of them, fail to parse with an error naming the two flags;
    /// each flow flag alone parses to itself.
    ///
    /// **Would red if:** a pair were accepted and one flag silently won.
    #[test]
    fn contradictory_login_flags_refuse_naming_both() {
        let flags = ["--api-key", "--device-code", "--browser", "--no-browser"];
        for (index, first) in flags.iter().enumerate() {
            for second in &flags[index + 1..] {
                let error = Cli::try_parse_from(["kata", "login", "openai", first, second])
                    .err()
                    .unwrap_or_else(|| panic!("{first} {second} parsed"))
                    .to_string();
                assert!(
                    error.contains(first) && error.contains(second),
                    "{first} {second}: {error}"
                );
            }
        }
        for (flag, expected) in [
            ("--device-code", (true, false, false)),
            ("--browser", (false, true, false)),
            ("--no-browser", (false, false, true)),
        ] {
            let cli = Cli::try_parse_from(["kata", "login", "openai", flag]).unwrap();
            let Command::Login {
                cmd:
                    LoginCmd::Openai {
                        api_key: false,
                        device_code,
                        browser,
                        no_browser,
                    },
            } = cli.command
            else {
                panic!("{flag} parsed to another command");
            };
            assert_eq!((device_code, browser, no_browser), expected, "{flag}");
        }
    }

    /// **The device-code prompt names the page, the code and its expiry.**
    #[test]
    fn the_device_code_prompt_names_the_page_the_code_and_its_expiry() {
        let prompt = device_code_prompt(&DeviceCode {
            verification_url: "https://issuer.invalid/codex/device".to_owned(),
            user_code: "ABCD-1234".to_owned(),
            expires_at_ms: 1_800_000_000_000,
        });
        assert!(
            prompt.contains("\n  https://issuer.invalid/codex/device\n"),
            "{prompt}"
        );
        assert!(prompt.contains("\n  ABCD-1234\n"), "{prompt}");
        assert!(
            prompt.contains("expires 2027-01-15T08:00:00+00:00"),
            "{prompt}"
        );
    }

    /// **`kata login status` reports each file by its own state, offline.**
    /// An absent directory reports every file absent with the command that
    /// writes it; a stored key reports stored; a group-readable one reports
    /// refused naming its path.
    #[test]
    fn login_status_reports_each_file_offline() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let dir = credential::logins_dir(home.path());
        let absent = render_status(&dir);
        assert!(
            absent.contains("openai-chatgpt.json: absent (`kata login openai` writes it)"),
            "{absent}"
        );
        assert!(
            absent.contains("anthropic-api-key: absent (`kata login anthropic --api-key`"),
            "{absent}"
        );

        credential::store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-status").unwrap();
        let stored = render_status(&dir);
        assert!(
            stored.contains("openai-api-key: an API key is stored"),
            "{stored}"
        );
        assert!(!stored.contains("sk-status"), "{stored}");

        let path = LoginFile::OpenAiApiKey.path(&dir);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let refused = render_status(&dir);
        assert!(
            refused.contains("openai-api-key: REFUSED, not owner-only"),
            "{refused}"
        );
        assert!(refused.contains(&path.display().to_string()), "{refused}");
    }

    /// **`kata login status --check` parses, and reports each file by its
    /// verdict's name; any stored login not `ok` fails it.** The flag parses
    /// to `Status { check: true }` and bare `status` to `check: false`. With
    /// nothing stored every file is `absent` and nothing fails; with both keys
    /// stored and their provider unreachable (a loopback port held bound and
    /// never listening for the whole cell, which a second bind is refused) each
    /// key is `unchecked` and named among the failed, the ChatGPT store
    /// `absent`; no key's value is printed.
    ///
    /// **Would red if:** the flag were unknown (its state before), a verdict
    /// were reported under another name, a login that did not check `ok` let
    /// the command succeed, or the dead port were released for a parallel
    /// cell's mock to bind and answer.
    #[test]
    fn login_status_check_names_each_verdict_and_fails_on_any_not_ok() {
        let cli = Cli::try_parse_from(["kata", "login", "status", "--check"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Login {
                cmd: LoginCmd::Status { check: true }
            }
        ));
        let cli = Cli::try_parse_from(["kata", "login", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Login {
                cmd: LoginCmd::Status { check: false }
            }
        ));

        // The unreachable provider: a loopback port held, until the last
        // check, by a socket bound without `SO_REUSEADDR` that never listens.
        // A connect to it is reset, and no other socket can bind the port while
        // it is held, so no parallel cell's mock can come to answer on it. A
        // port read off a dropped `127.0.0.1:0` listener is free for the next
        // bind to take.
        let held = tokio::net::TcpSocket::new_v4().unwrap();
        held.bind(([127, 0, 0, 1], 0).into()).unwrap();
        let dead = held.local_addr().unwrap();
        assert_eq!(
            std::net::TcpListener::bind(dead)
                .map(drop)
                .map_err(|error| error.kind()),
            Err(std::io::ErrorKind::AddrInUse),
            "another socket could bind the dead port {dead}"
        );
        let hosts = credential::CheckHosts::local_for_test(&format!("http://{dead}"));
        let home = tempfile::tempdir().unwrap();
        let dir = credential::logins_dir(home.path());
        let (report, verdict) = render_check(&dir, &hosts);
        assert!(verdict.is_ok(), "{report}");
        for file in LoginFile::ALL {
            assert!(
                report.contains(&format!("  {}: absent: ", file.file_name())),
                "{report}"
            );
        }

        credential::store_api_key(&dir, LoginFile::OpenAiApiKey, "sk-check-a").unwrap();
        credential::store_api_key(&dir, LoginFile::AnthropicApiKey, "sk-check-b").unwrap();
        let (report, verdict) = render_check(&dir, &hosts);
        let refusal = verdict.expect_err("a stored login that is not `ok` fails the command");
        assert_eq!(
            refusal.to_string(),
            "2 stored login(s) did not check `ok`: openai-api-key, anthropic-api-key",
            "{report}"
        );
        assert!(report.contains("  openai-api-key: unchecked: "), "{report}");
        assert!(
            report.contains("  anthropic-api-key: unchecked: "),
            "{report}"
        );
        assert!(
            report.contains("  openai-chatgpt.json: absent: "),
            "{report}"
        );
        assert!(!report.contains("sk-check"), "{report}");
        drop(held);
    }
}
