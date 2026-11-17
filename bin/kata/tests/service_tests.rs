use std::collections::BTreeMap;

use clap::Parser;
use kata::cli::Cli;
use kata::service::{ServiceAction, ServicePlatform, ServiceSpec};
use tempfile::TempDir;

fn fixture(platform: ServicePlatform) -> (TempDir, ServiceSpec) {
    let temp = TempDir::new().unwrap();
    let binary = temp.path().join("kata bin");
    let config = temp.path().join("kata.toml");
    std::fs::write(&binary, b"binary").unwrap();
    std::fs::write(&config, b"[node]\n").unwrap();
    let data = temp.path().join("durable data");
    let mut env = BTreeMap::new();
    env.insert("RUST_LOG".to_string(), "kata=info".to_string());
    let spec = ServiceSpec::new_for_test(platform, &binary, &config, &data, env).unwrap();
    (temp, spec)
}

#[test]
fn systemd_user_definition_runs_one_foreground_main() {
    let (_temp, spec) = fixture(ServicePlatform::SystemdUser);
    let unit = spec.render();
    assert!(unit.contains("ExecStart="));
    assert!(unit.contains("\"__service-exec\" \"--definition\""));
    assert!(unit.contains("\"--environment\""));
    assert!(unit.contains("\"--config\""));
    assert!(unit.contains("\"--expected-binary-digest\""));
    assert!(unit.contains("\"--expected-config-digest\""));
    assert!(unit.contains("\"--expected-environment-digest\""));
    assert!(unit.contains("\"--expected-data-directory\""));
    assert!(unit.contains("\"--expected-directory-id\""));
    assert!(unit.contains(&spec.binary_digest));
    assert!(unit.contains(&spec.config_digest));
    assert!(unit.contains(&spec.environment_digest));
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("TimeoutStopSec=30s"));
    assert!(unit.contains("KillMode=control-group"));
    assert!(
        unit.lines().any(|line| line == "Delegate=yes"),
        "the unit must delegate its cgroup so a capsule stage's container can be bounded"
    );
    assert!(!unit.contains("RUST_LOG=kata=info"));
    assert!(unit.contains(&spec.environment_path.to_string_lossy().to_string()));
    assert!(unit.contains("X-Kata-Config-Digest="));
    assert!(unit.contains("X-Kata-Binary-Digest="));
    assert!(unit.contains("X-Kata-Binary-Version="));
    assert!(unit.contains("X-Kata-Binary-Path="));
    assert_eq!(
        kata::service::definition_binary_digest(&unit).as_deref(),
        Some(spec.binary_digest.as_str())
    );
    assert_eq!(
        kata::service::definition_binary_path(&unit).as_deref(),
        Some(spec.binary.as_path())
    );
    assert!(unit.contains("X-Kata-Data-Directory-ID=uninitialized"));
    assert!(unit.contains(&format!(
        "WorkingDirectory={}",
        spec.config.parent().unwrap().display()
    )));
    assert!(!unit.contains("--role"));
    assert!(!unit.contains("sudo"));

    let plan = spec.plan(ServiceAction::Start).unwrap();
    assert_eq!(
        plan.commands,
        vec![vec![
            "/usr/bin/systemctl",
            "--user",
            "enable",
            "--now",
            "kata.service"
        ]]
    );
}

#[test]
fn launchagent_definition_runs_same_foreground_entrypoint() {
    let (_temp, spec) = fixture(ServicePlatform::LaunchdAppleSilicon);
    let plist = spec.render();
    assert!(plist.contains("<string>__service-exec</string>"));
    assert!(plist.contains("<string>--environment</string>"));
    assert!(plist.contains("<string>--config</string>"));
    assert!(plist.contains("<string>--expected-binary-digest</string>"));
    assert!(plist.contains("<string>--expected-config-digest</string>"));
    assert!(plist.contains("<string>--expected-environment-digest</string>"));
    assert!(plist.contains("<string>--expected-data-directory</string>"));
    assert!(plist.contains("<string>--expected-directory-id</string>"));
    assert!(plist.contains(&spec.binary_digest));
    assert!(plist.contains(&spec.config_digest));
    assert!(plist.contains(&spec.environment_digest));
    assert!(plist.contains("<key>KeepAlive</key>"));
    assert!(plist.contains("<key>ExitTimeOut</key><integer>30</integer>"));
    assert!(!plist.contains("StandardOutPath"));
    assert!(!plist.contains("StandardErrorPath"));
    assert!(!plist.contains("main.stdout.log"));
    assert!(!plist.contains("main.stderr.log"));
    assert!(!plist.contains("RUST_LOG=kata=info"));
    assert!(plist.contains(&spec.environment_path.to_string_lossy().to_string()));
    assert!(plist.contains("<key>KataConfigDigest</key>"));
    assert!(plist.contains("<key>KataBinaryDigest</key>"));
    assert!(plist.contains("<key>KataBinaryVersion</key>"));
    assert!(plist.contains("<key>KataBinaryPath</key>"));
    assert_eq!(
        kata::service::definition_binary_digest(&plist).as_deref(),
        Some(spec.binary_digest.as_str())
    );
    assert_eq!(
        kata::service::definition_binary_path(&plist).as_deref(),
        Some(spec.binary.as_path())
    );
    assert!(plist.contains(&format!(
        "<key>WorkingDirectory</key><string>{}</string>",
        spec.config.parent().unwrap().display()
    )));
    assert!(!plist.contains("--role"));
}

#[test]
fn service_environment_is_strictly_bounded() {
    let temp = TempDir::new().unwrap();
    let binary = temp.path().join("kata");
    let config = temp.path().join("kata.toml");
    std::fs::write(&binary, b"binary").unwrap();
    std::fs::write(&config, b"[node]\n").unwrap();
    let mut env = BTreeMap::new();
    env.insert("LD_PRELOAD".to_string(), "/tmp/hook.so".to_string());
    let error = ServiceSpec::new_for_test(
        ServicePlatform::SystemdUser,
        &binary,
        &config,
        &temp.path().join("data"),
        env,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("bounded allowlist"));
}

#[test]
fn service_secret_values_are_only_in_owner_environment_source() {
    let (_temp, mut spec) = fixture(ServicePlatform::SystemdUser);
    spec.environment.insert(
        "KATA_API_TOKEN".to_string(),
        "super-secret-token".to_string(),
    );
    let plan = spec.plan(ServiceAction::Install).unwrap();
    assert!(!plan.definition.contains("super-secret-token"));
    assert!(plan.environment_definition.contains("super-secret-token"));
    assert_eq!(
        kata::service::definition_directory_id(&plan.definition).as_deref(),
        Some("uninitialized")
    );
    assert_eq!(
        kata::service::definition_data_dir(&plan.definition).as_deref(),
        Some(spec.data_dir.as_path())
    );
}

#[test]
fn systemd_service_can_preserve_the_bounded_xdg_attachment_root() {
    let (_temp, mut spec) = fixture(ServicePlatform::SystemdUser);
    spec.environment
        .insert("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string());
    let plan = spec.plan(ServiceAction::Install).unwrap();
    assert!(!plan.definition.contains("XDG_RUNTIME_DIR=/run/user/1000"));
    assert!(plan.environment_definition.contains("XDG_RUNTIME_DIR"));
}

#[test]
fn uninstall_plan_never_names_or_removes_data() {
    let (_temp, spec) = fixture(ServicePlatform::SystemdUser);
    let plan = spec.plan(ServiceAction::Uninstall).unwrap();
    let commands = format!("{:?}", plan.commands);
    assert!(!commands.contains(&spec.data_dir.to_string_lossy().to_string()));
    assert!(commands.contains("disable"));
    assert!(commands.contains("daemon-reload"));
}

#[test]
fn config_content_and_directory_identity_are_bound_into_definition() {
    let (temp, first) = fixture(ServicePlatform::SystemdUser);
    let first_definition = first.render();
    std::fs::write(&first.config, b"[node]\nid = \"changed\"\n").unwrap();
    std::fs::create_dir_all(&first.data_dir).unwrap();
    std::fs::write(
        first.data_dir.join("main-identity.json"),
        br#"{"directory_id":"dir-123","format_generation":7,"mode":"installed"}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            first.data_dir.join("main-identity.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let second = ServiceSpec::new_for_test(
        ServicePlatform::SystemdUser,
        &first.binary,
        &first.config,
        &first.data_dir,
        first.environment.clone(),
    )
    .unwrap();
    assert_ne!(first_definition, second.render());
    assert!(second.render().contains("X-Kata-Data-Directory-ID=dir-123"));
    drop(temp);
}

#[test]
fn only_install_accepts_a_config_argument() {
    assert!(Cli::try_parse_from(["kata", "service", "install", "--config", "kata.toml"]).is_ok());
    for action in ["start", "stop", "restart", "status", "logs", "uninstall"] {
        assert!(
            Cli::try_parse_from(["kata", "service", action]).is_ok(),
            "{action}"
        );
        assert!(
            Cli::try_parse_from(["kata", "service", action, "--config", "broken.toml"]).is_err(),
            "{action} unexpectedly accepted --config"
        );
    }
}

#[test]
fn systemd_percent_specifiers_are_rendered_as_literals() {
    let (temp, mut spec) = fixture(ServicePlatform::SystemdUser);
    let binary = temp.path().join("kata%ibin");
    std::fs::write(&binary, b"binary").unwrap();
    spec.binary = binary.canonicalize().unwrap();
    spec.environment
        .insert("RUST_LOG".into(), "kata%=info".into());
    let unit = spec.render();
    assert!(unit.contains("kata%%ibin"));
    assert!(!unit.contains("kata%%=info"));
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "service_tests/installed_main_inherited_fd_tests.rs"]
mod installed_main_inherited_fd_tests;
