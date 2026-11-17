//! `kata run` has no daemon-free face. `--scratch` and `--config` are not arguments
//! of `kata run`, so clap's own unknown-argument error refuses either at parse — exit
//! `2`, before a config is read, a directory is made or a main is dialled. Read off the
//! real binary's exit status and stderr, the absence of anything in the private
//! `TMPDIR` and working directory the process was given, and a listener standing in
//! for the main that no connection reaches.

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A node config a `--config` could name. Nothing may read it: the refusal precedes
/// any config load, so its `data_dir` must never appear.
fn config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("kata.toml");
    std::fs::write(
        &path,
        format!(
            "[node]\nid = \"run-flag-refusal\"\ndata_dir = \"{data}\"\n\n[agents.default]\ntype = \
             \"shell\"\n",
            data = dir.join("data").display(),
        ),
    )
    .unwrap();
    path
}

#[test]
fn kata_run_refuses_scratch_and_config_as_unknown_arguments_at_parse() {
    let dir = tempfile::tempdir().unwrap();
    // A private TMPDIR and working directory, so "nothing was created" is observable.
    let tmp = dir.path().join("tmp");
    let cwd = dir.path().join("cwd");
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    let pack = dir.path().join("probe.star");
    std::fs::write(
        &pack,
        "probe = stage(id = \"probe\", agent = \"shell\", run = \"true\")\nworkflow(\"probe\", \
         root = [probe])\n",
    )
    .unwrap();
    let pack = pack.to_str().unwrap().to_owned();
    let config = config(dir.path());
    let config = config.to_str().unwrap().to_owned();
    // A secret typed on the command line must not come back in the refusal. Clap
    // stops at the first unknown argument, so the secret is passed BEFORE the refused
    // flag: it is parsed, and the refusal could echo it.
    let secret = "api_token=sentinel-lowercase-secret-must-not-leak";
    // The main's stand-in: every connection is counted and dropped at once, so a
    // binary that dialled it fails fast instead of waiting out an attach timeout.
    let main = TcpListener::bind("127.0.0.1:0").unwrap();
    main.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}", main.local_addr().unwrap());
    let dials = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let counter = {
        let (dials, stop) = (Arc::clone(&dials), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match main.accept() {
                    Ok(_) => {
                        dials.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("main stand-in accept failed: {error}"),
                }
            }
        })
    };

    let cases: [(&str, Vec<&str>); 6] = [
        ("--scratch", vec!["run", &pack, "--scratch"]),
        (
            "--scratch",
            vec![
                "run",
                &pack,
                "--param",
                secret,
                "--scratch",
                "--config",
                &config,
            ],
        ),
        ("--config", vec!["run", &pack, "--config", &config]),
        (
            "--config",
            vec!["run", &pack, "--wait", "--config", &config],
        ),
        (
            "--config",
            vec!["run", &pack, "--submit", "--config", &config],
        ),
        ("--config", vec!["run", "list", "--config", &config]),
    ];
    for (refused, argv) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_kata"))
            .current_dir(&cwd)
            .env("TMPDIR", &tmp)
            .env("HOME", dir.path())
            .env("KATA_API_URL", &api_url)
            .env("KATA_NO_DOTENV", "1")
            .args(&argv)
            .output()
            .expect("the kata binary runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Accept is polled; give a connection made just before exit time to land.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(
            dials.load(Ordering::SeqCst),
            0,
            "{argv:?} dialled the main: stdout={stdout} stderr={stderr}"
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{argv:?} must be clap's usage error (exit 2): stdout={stdout} stderr={stderr}"
        );
        assert!(
            stderr.contains(&format!("unexpected argument '{refused}' found")),
            "{argv:?} is refused by clap naming `{refused}`: {stderr}"
        );
        assert!(
            !stderr.contains("sentinel-lowercase-secret")
                && !stdout.contains("sentinel-lowercase-secret"),
            "{argv:?}: the refusal echoes no --param value: stdout={stdout} stderr={stderr}"
        );
    }

    stop.store(true, Ordering::SeqCst);
    counter.join().unwrap();

    for (what, path) in [("TMPDIR", &tmp), ("working directory", &cwd)] {
        let created: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            created.is_empty(),
            "refused before anything lands in the {what}: {created:?}"
        );
    }
    assert!(
        !dir.path().join("data").exists(),
        "the named config was never loaded, so its data_dir was never made"
    );
}
