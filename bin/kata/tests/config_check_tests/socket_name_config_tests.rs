//! The one bound left on a local worker socket's path — its file NAME — refused at
//! boot and in `kata doctor`, and only past it. Spawns the product against a config
//! that declares no model agent (`gate_exclusion`'s rule for gate-reachable spawns).

/// A `local_socket` config whose file name is `name_len` bytes, under a data
/// directory far longer than the kernel's 108-byte `sun_path`.
fn long_data_dir_socket_config(dir: &std::path::Path, name_len: usize) -> std::path::PathBuf {
    let mut data_dir = dir.join("data");
    while data_dir.as_os_str().len() < 200 {
        data_dir.push("d".repeat(40));
    }
    let path = dir.join("kata.toml");
    std::fs::write(
        &path,
        format!(
            "[node]\nid = \"socket-name-main\"\ndata_dir = \"{data}\"\n\n\
             [workers]\ntransports = [{{ type = \"local_socket\", path = \"{name}\" }}]\n\
             dispatch_deadline_ms = 5000\nheartbeat_interval_ms = 2500\n\
             heartbeat_grace_ms = 10000\nmax_workers = 4\n\n\
             [api]\nbind = \"127.0.0.1:0\"\nauth = {{ type = \"disabled\" }}\n",
            data = data_dir.display(),
            name = "w".repeat(name_len),
        ),
    )
    .unwrap();
    path
}

/// **A local worker socket's NAME is the one bound left, refused at boot and in
/// `kata doctor` — and only past it.** The socket is addressed through its
/// parent's descriptor, so a 200-byte `data_dir` is admitted; an 83-byte file
/// name cannot fit `/proc/self/fd/<fd>/<name>` for every descriptor and is
/// refused by `kata serve` and `kata doctor` alike, naming the 82-byte limit and
/// the offending path. The 82-byte twin passes `config_validation` and boots past
/// config load (it stops later, at the undeclared node environment — not here).
#[test]
fn an_overlong_local_socket_name_is_refused_at_boot_and_in_doctor_and_its_edge_is_not() {
    for (name_len, refused) in [(83_usize, true), (82, false)] {
        let dir = tempfile::tempdir().unwrap();
        let config = long_data_dir_socket_config(dir.path(), name_len);
        let limit = "may be at most 82 bytes";

        let doctor = std::process::Command::new(env!("CARGO_BIN_EXE_kata"))
            .args(["doctor", "--format", "json", "--config"])
            .arg(&config)
            .current_dir(dir.path())
            .output()
            .expect("kata doctor runs");
        let stdout = String::from_utf8_lossy(&doctor.stdout).into_owned();
        let report: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("doctor emits one report ({error}): {stdout}"));
        let row = report["checks"]
            .as_array()
            .and_then(|checks| {
                checks
                    .iter()
                    .find(|check| check["name"] == "config_validation")
            })
            .unwrap_or_else(|| panic!("a config_validation row: {stdout}"))
            .clone();
        let text = row.to_string();
        if refused {
            assert_eq!(row["status"], "fail", "{text}");
            assert!(text.contains(limit), "doctor names the limit: {text}");
            assert!(
                text.contains(&"w".repeat(83)),
                "doctor names the offending name: {text}"
            );
        } else {
            assert_eq!(row["status"], "pass", "the 82-byte edge validates: {text}");
        }

        let serve = std::process::Command::new(env!("CARGO_BIN_EXE_kata"))
            .args(["serve", "--config"])
            .arg(&config)
            .current_dir(dir.path())
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kata serve runs");
        let stderr = String::from_utf8_lossy(&serve.stderr).into_owned();
        assert!(
            !serve.status.success(),
            "neither config boots a node here: {stderr}"
        );
        assert_eq!(
            stderr.contains(limit),
            refused,
            "boot refuses the {name_len}-byte name by the limit iff it is past it: {stderr}"
        );
    }
}
