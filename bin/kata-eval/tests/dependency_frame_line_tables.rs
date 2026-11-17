//! **A DEPENDENCY frame in a kata backtrace keeps its `file:line`.**
//!
//! Dropping dependency line tables is refused, not merely untaken: a backtrace
//! whose dependency frames have no `file:line` costs every later debugging
//! session, and that cost is paid by somebody else, later.
//!
//! The refused arm is `[profile.dev.package."*"] debug = false`. It is worth a
//! MEASURED 1.38x wall-clock and 2x disk (root `Cargo.toml`, the four-arm table
//! above `[profile.dev]`), and the table it belongs in **already exists** one
//! line below that comment — it is there for `opt-level = 2`. A refusal that
//! valuable, that easy to re-take, and whose cost shows up only later in
//! somebody else's stack trace is exactly the kind a comment does not hold. So
//! it is machine-checked here, in the shape [`gate_exclusion`] uses next door:
//! a check that reads the config file, not a comment that describes it.
//!
//! # What this proves, and what it does not
//!
//! PROVES: the profile a dependency compiles under still ASKS for line tables,
//! against every FILE-SHAPED way this repo has to take the refused arm. There
//! are four, and each has its own check because each is one line from being
//! written:
//!
//! 1. `[profile.dev.package."*"] debug` / `[profile.dev] debug` — the refused
//!    arm itself, resolved by [`resolve_dependency_debug`].
//! 2. `[profile.dev.package.<spec>] debug` for a NAMED spec (tokio, the
//!    commonware pins). Swept by [`per_package_debug_overrides`].
//! 3. `strip` in either of those tables. `strip = "debuginfo"` / `"symbols"` /
//!    `true` removes the very line tables (1) and (2) were checked to request —
//!    and the root manifest ALREADY uses `strip = true` under `[profile.release]`
//!    one screen above `[profile.dev]`, so this is a copy-paste away. Resolved by
//!    [`resolve_dependency_strip`] and swept by [`per_package_strip_overrides`].
//! 4. `rustflags` in `.cargo/config.toml` — `-C debuginfo=0`, `-C
//!    strip=debuginfo` and friends. Cargo APPENDS these after the
//!    profile-derived flags, so they win over everything above. Checked by
//!    [`cargo_config_declares_no_profile_override`].
//!
//! # How the resolver treats named specs, stated exactly
//!
//! [`resolve_dependency_debug`] reads only `[profile.dev.package."*"]` and
//! `[profile.dev]`. It does NOT implement cargo's full per-spec precedence, and
//! its `Resolution` is therefore the level a dependency with NO named override
//! compiles at — for `[profile.dev] debug = "line-tables-only"` plus
//! `[profile.dev.package.tokio] debug = false` and no `"*"`, it returns
//! line-tables and names `[profile.dev]`, which is false OF TOKIO.
//!
//! That does not weaken the VERDICT, because the separate per-spec sweep refuses
//! ANY named spec whose level carries no line table, whatever the resolver said —
//! so the pair is strictly stricter than cargo's own precedence, and the manifest
//! above reds on the tokio row. It does mean the resolver's `source` string names
//! the line to edit only for the unnamed case. A per-spec resolver would let the
//! failure message name the exact row in every case; it is not built because the
//! sweep already refuses the same manifests and a second precedence
//! implementation is a second thing to keep true.
//!
//! DOES NOT PROVE: that a symbolizer then FINDS them. `split-debuginfo =
//! "unpacked"` leaves the DWARF beside the binary, and whether a given host's
//! symbolizer follows it is a property of the host, not of this manifest. An
//! empirical arm was considered — capture a [`std::backtrace::Backtrace`]
//! through a dependency frame and assert the `at <file>:<line>` suffix — and NOT
//! taken: it would red on a host whose symbolizer differs while the manifest is
//! correct, which reports a build-profile defect that is not there. The
//! manifest-side claim is the one this repo can make everywhere it builds.
//!
//! ALSO NOT COVERED, named rather than left as a silent gap: the environment.
//! `CARGO_PROFILE_DEV_PACKAGE_*_DEBUG`, `CARGO_PROFILE_DEV_STRIP` and `RUSTFLAGS`
//! all outrank every file here, and no file in this repo can see them.
//!
//! [`gate_exclusion`]: ../gate_exclusion.rs

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/bin/kata-eval")
        .to_path_buf()
}

fn root_manifest_text() -> String {
    let path = repo_root().join("Cargo.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading workspace manifest {}: {e}", path.display()))
}

/// Cargo's `debug` levels, in the spelling `[profile.*]` accepts.
///
/// Ordering is deliberate and is NOT `Ord`: `LineDirectivesOnly` emits line-info
/// directives without a usable line table, so it sits with `None` on the side
/// this check refuses even though it is "more" debuginfo than `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugLevel {
    None,
    LineDirectivesOnly,
    LineTables,
    Limited,
    Full,
}

impl DebugLevel {
    /// Does a frame compiled at this level carry `file:line`?
    fn carries_line_tables(self) -> bool {
        match self {
            Self::LineTables | Self::Limited | Self::Full => true,
            Self::None | Self::LineDirectivesOnly => false,
        }
    }
}

/// Cargo's documented default for the `dev` profile when no `debug` key is set.
const CARGO_DEV_DEFAULT: DebugLevel = DebugLevel::Full;

/// Parse one `debug = …` value. An UNRECOGNISED spelling is an error, never a
/// pass: a future cargo level this test has not been taught must red and be
/// classified by a human, not be waved through as "probably fine".
fn parse_debug(value: &toml::Value) -> Result<DebugLevel, String> {
    if let Some(b) = value.as_bool() {
        return Ok(if b {
            DebugLevel::Full
        } else {
            DebugLevel::None
        });
    }
    if let Some(i) = value.as_integer() {
        return match i {
            0 => Ok(DebugLevel::None),
            1 => Ok(DebugLevel::Limited),
            2 => Ok(DebugLevel::Full),
            other => Err(format!("unrecognised numeric debug level {other}")),
        };
    }
    if let Some(s) = value.as_str() {
        return match s {
            "none" => Ok(DebugLevel::None),
            "line-directives-only" => Ok(DebugLevel::LineDirectivesOnly),
            "line-tables-only" => Ok(DebugLevel::LineTables),
            "limited" => Ok(DebugLevel::Limited),
            "full" => Ok(DebugLevel::Full),
            other => Err(format!("unrecognised debug level {other:?}")),
        };
    }
    Err(format!(
        "debug must be bool, integer or string, got {value}"
    ))
}

/// Where a resolved level came from, so a failure names the line to edit.
///
/// Generic over the level so `debug` and `strip` share one shape rather than
/// growing a second, subtly-different struct beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolution<T> {
    level: T,
    source: String,
}

/// Resolve the `debug` level a DEPENDENCY package compiles under in the `dev`
/// profile, the way cargo resolves it: the `[profile.dev.package."*"]` override
/// if present, else `[profile.dev]`, else cargo's own dev default.
///
/// Never returns "nothing found": the default arm is an explicit, named
/// observation, so this cannot be satisfied by an ABSENT profile table.
///
/// It reads only the `"*"` glob. A NAMED `[profile.dev.package.<spec>] debug`
/// would beat both tables in cargo and is deliberately NOT resolved here — the
/// separate [`per_package_debug_overrides`] sweep refuses any such spec outright,
/// which is stricter. See this module's doc for what that costs (the `source`
/// string names the editable line only for the unnamed case) and why a second
/// precedence implementation was not written.
fn resolve_dependency_debug(manifest: &toml::Value) -> Result<Resolution<DebugLevel>, String> {
    let dev = manifest.get("profile").and_then(|p| p.get("dev"));

    let mut resolved = Resolution {
        level: CARGO_DEV_DEFAULT,
        source: "cargo's built-in dev default (no `[profile.dev] debug`)".to_string(),
    };

    if let Some(value) = dev.and_then(|d| d.get("debug")) {
        resolved = Resolution {
            level: parse_debug(value).map_err(|e| format!("[profile.dev] debug: {e}"))?,
            source: "[profile.dev] debug".to_string(),
        };
    }

    if let Some(value) = dev
        .and_then(|d| d.get("package"))
        .and_then(|p| p.get("*"))
        .and_then(|glob| glob.get("debug"))
    {
        resolved = Resolution {
            level: parse_debug(value)
                .map_err(|e| format!("[profile.dev.package.\"*\"] debug: {e}"))?,
            source: "[profile.dev.package.\"*\"] debug".to_string(),
        };
    }

    Ok(resolved)
}

/// Every `[profile.dev.package.<spec>]` that sets `debug`, in manifest order.
/// The `"*"` glob is included — [`resolve_dependency_debug`] reads it too, and
/// listing it here keeps the per-spec failure message complete.
fn per_package_debug_overrides(
    manifest: &toml::Value,
) -> Result<Vec<(String, DebugLevel)>, String> {
    per_package_key(manifest, "debug", parse_debug)
}

/// Cargo's `strip` levels, in the spelling `[profile.*]` accepts.
///
/// `strip` is a per-package-overridable key (verified: cargo consumes
/// `--config 'profile.dev.package."*".strip="symbols"'` with no *"unused config
/// key"* warning, which it DOES emit for an unrecognised one), so it can take
/// the refused arm from the same two tables `debug` can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StripLevel {
    None,
    Debuginfo,
    Symbols,
}

impl StripLevel {
    /// Do the line tables the `debug` level asked for SURVIVE this strip level?
    ///
    /// Only `none` leaves them. `debuginfo` removes exactly them; `symbols`
    /// removes them and the symbol table too.
    fn keeps_line_tables(self) -> bool {
        matches!(self, Self::None)
    }
}

/// Cargo's own default: nothing is stripped unless a profile says so.
const CARGO_STRIP_DEFAULT: StripLevel = StripLevel::None;

/// Parse one `strip = …` value. As with [`parse_debug`], an UNRECOGNISED
/// spelling is an error and never a pass.
fn parse_strip(value: &toml::Value) -> Result<StripLevel, String> {
    if let Some(b) = value.as_bool() {
        // Cargo documents `strip = true` as equivalent to `"symbols"`.
        return Ok(if b {
            StripLevel::Symbols
        } else {
            StripLevel::None
        });
    }
    if let Some(s) = value.as_str() {
        return match s {
            "none" => Ok(StripLevel::None),
            "debuginfo" => Ok(StripLevel::Debuginfo),
            "symbols" => Ok(StripLevel::Symbols),
            other => Err(format!("unrecognised strip level {other:?}")),
        };
    }
    Err(format!("strip must be bool or string, got {value}"))
}

/// Resolve the `strip` level a DEPENDENCY package compiles under in the `dev`
/// profile, with the same precedence [`resolve_dependency_debug`] uses.
///
/// # Why this is not folded into the `debug` check
///
/// A profile that ASKS for line tables and then strips them ships binaries with
/// no `file:line`, which is the refused outcome — reached by a different
/// key, in the same two tables, and one the root manifest already writes
/// (`[profile.release] strip = true`, one screen above `[profile.dev]`). Two
/// resolutions, one verdict: [`dependency_frames_keep_file_line_under_the_dev_profile`]
/// fails if EITHER says no.
fn resolve_dependency_strip(manifest: &toml::Value) -> Result<Resolution<StripLevel>, String> {
    let dev = manifest.get("profile").and_then(|p| p.get("dev"));

    let mut resolved = Resolution {
        level: CARGO_STRIP_DEFAULT,
        source: "cargo's built-in dev default (no `[profile.dev] strip`)".to_string(),
    };

    if let Some(value) = dev.and_then(|d| d.get("strip")) {
        resolved = Resolution {
            level: parse_strip(value).map_err(|e| format!("[profile.dev] strip: {e}"))?,
            source: "[profile.dev] strip".to_string(),
        };
    }

    if let Some(value) = dev
        .and_then(|d| d.get("package"))
        .and_then(|p| p.get("*"))
        .and_then(|glob| glob.get("strip"))
    {
        resolved = Resolution {
            level: parse_strip(value)
                .map_err(|e| format!("[profile.dev.package.\"*\"] strip: {e}"))?,
            source: "[profile.dev.package.\"*\"] strip".to_string(),
        };
    }

    Ok(resolved)
}

/// Every `[profile.dev.package.<spec>]` that sets `strip`, in manifest order.
fn per_package_strip_overrides(
    manifest: &toml::Value,
) -> Result<Vec<(String, StripLevel)>, String> {
    per_package_key(manifest, "strip", parse_strip)
}

/// The shared sweep behind [`per_package_debug_overrides`] and
/// [`per_package_strip_overrides`]: every `[profile.dev.package.<spec>]` that
/// sets `key`, in manifest order. The `"*"` glob is included — the resolvers read
/// it too, and listing it here keeps the per-spec failure message complete.
fn per_package_key<T>(
    manifest: &toml::Value,
    key: &str,
    parse: fn(&toml::Value) -> Result<T, String>,
) -> Result<Vec<(String, T)>, String> {
    let Some(table) = manifest
        .get("profile")
        .and_then(|p| p.get("dev"))
        .and_then(|d| d.get("package"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (spec, body) in table {
        if let Some(value) = body.get(key) {
            let level =
                parse(value).map_err(|e| format!("[profile.dev.package.{spec:?}] {key}: {e}"))?;
            out.push((spec.clone(), level));
        }
    }
    Ok(out)
}

/// THE RULE. A dependency frame in a `dev`-profile backtrace carries
/// `file:line`.
#[test]
fn dependency_frames_keep_file_line_under_the_dev_profile() {
    let manifest: toml::Value = toml::from_str(&root_manifest_text())
        .unwrap_or_else(|e| panic!("parsing the workspace manifest: {e}"));

    let resolved = resolve_dependency_debug(&manifest).expect("resolving the dev debug level");
    assert!(
        resolved.level.carries_line_tables(),
        "kata keeps dependency line tables, and this drops them: a dependency compiles at \
         {:?}, set by `{}` in the root Cargo.toml, which carries NO line table — so every \
         dependency frame in every kata backtrace loses its file:line. The 1.38x wall and 2x \
         disk are real and were weighed against that. Restore a line-table-bearing level; \
         changing the rule means changing this test, deliberately.",
        resolved.level,
        resolved.source,
    );

    // The `"*"` glob is not the only way to take the refused arm: naming tokio,
    // or the pinned commonware crates, one spec at a time reaches the same
    // place — and those are the exact frames a kata backtrace needs.
    for (spec, level) in
        per_package_debug_overrides(&manifest).expect("reading per-package debug overrides")
    {
        assert!(
            level.carries_line_tables(),
            "kata keeps dependency line tables, and this drops them: \
             `[profile.dev.package.{spec:?}] debug` is {level:?}, which \
             carries no line table. Per-package is the same refusal as the `\"*\"` glob, one \
             spec at a time."
        );
    }

    // A profile that ASKS for line tables and then STRIPS them ships the refused
    // arm's outcome through a different key. The root manifest already writes
    // `strip = true` under `[profile.release]`, one screen above `[profile.dev]`,
    // so this is a copy-paste from inside the same file.
    let stripped = resolve_dependency_strip(&manifest).expect("resolving the dev strip level");
    assert!(
        stripped.level.keeps_line_tables(),
        "kata keeps dependency line tables, and `{}` in the root Cargo.toml drops them by a \
         different key: strip is {:?}, which removes the line tables `{}` was just checked to \
         REQUEST. Asking for debuginfo and then stripping it ships binaries with no file:line \
         exactly as `debug = false` would. Restore `strip = \"none\"` (or delete the key — \
         cargo's dev default strips nothing).",
        stripped.source,
        stripped.level,
        resolved.source,
    );
    for (spec, level) in
        per_package_strip_overrides(&manifest).expect("reading per-package strip overrides")
    {
        assert!(
            level.keeps_line_tables(),
            "kata keeps dependency line tables, and this drops them: \
             `[profile.dev.package.{spec:?}] strip` is \
             {level:?}, which removes that dependency's line tables. Same refusal as the \
             `\"*\"` glob, one spec at a time."
        );
    }
}

/// The counterfactual, in-tree: prove the resolver above can say NO.
///
/// Without this, [`dependency_frames_keep_file_line_under_the_dev_profile`] is
/// satisfiable by a resolver that returns [`DebugLevel::Full`] for everything —
/// a check that passes by observing nothing. Each case here is a manifest a
/// human could actually write, and the first is verbatim the refused arm.
#[test]
fn the_resolver_reds_on_the_refused_arm() {
    let case = |text: &str| {
        let manifest: toml::Value = toml::from_str(text).expect("fixture manifest parses");
        resolve_dependency_debug(&manifest).expect("fixture resolves")
    };

    // The refused arm, spelled exactly.
    let refused = case(
        "[profile.dev]\ndebug = \"line-tables-only\"\n\n[profile.dev.package.\"*\"]\ndebug = false\n",
    );
    assert_eq!(refused.level, DebugLevel::None);
    assert!(!refused.level.carries_line_tables());
    assert_eq!(refused.source, "[profile.dev.package.\"*\"] debug");

    // Its near-miss: line-info directives are not a line table.
    let directives = case("[profile.dev.package.\"*\"]\ndebug = \"line-directives-only\"\n");
    assert_eq!(directives.level, DebugLevel::LineDirectivesOnly);
    assert!(!directives.level.carries_line_tables());

    // The glob OUTRANKS `[profile.dev]`, which is why reading one key is not
    // enough: this manifest looks compliant on its first table and is not.
    let outranked = case("[profile.dev]\ndebug = 2\n\n[profile.dev.package.\"*\"]\ndebug = 0\n");
    assert!(!outranked.level.carries_line_tables());

    // No profile at all still resolves to a NAMED value, not to a skip.
    let bare = case("[workspace]\nmembers = []\n");
    assert_eq!(bare.level, CARGO_DEV_DEFAULT);
    assert!(bare.level.carries_line_tables());
    assert!(bare.source.contains("cargo's built-in dev default"));

    // The shipped level passes, so the two arms are not both stuck on "no".
    let shipped = case("[profile.dev]\ndebug = \"line-tables-only\"\n");
    assert_eq!(shipped.level, DebugLevel::LineTables);
    assert!(shipped.level.carries_line_tables());

    // An unrecognised level is an ERROR, not a pass.
    let manifest: toml::Value = toml::from_str("[profile.dev]\ndebug = \"whatever\"\n").unwrap();
    assert!(resolve_dependency_debug(&manifest).is_err());
}

/// The counterfactual for the STRIP arm: prove that resolver can say NO too.
///
/// Same job as [`the_resolver_reds_on_the_refused_arm`] next door. Without
/// it, the `strip` half of
/// [`dependency_frames_keep_file_line_under_the_dev_profile`] is satisfiable by a
/// resolver that returns [`StripLevel::None`] for everything — and it WOULD, on
/// today's manifest, which sets no `strip` under `[profile.dev]` at all.
#[test]
fn the_strip_resolver_reds_on_a_profile_that_strips_what_it_asked_for() {
    let case = |text: &str| {
        let manifest: toml::Value = toml::from_str(text).expect("fixture manifest parses");
        resolve_dependency_strip(&manifest).expect("fixture resolves")
    };

    // The shape one screen up in the real manifest — `[profile.release] strip =
    // true` — copied down into the dev profile. `true` is cargo's spelling of
    // "symbols", which takes the line tables with it.
    let copied_from_release = case("[profile.dev]\ndebug = \"line-tables-only\"\nstrip = true\n");
    assert_eq!(copied_from_release.level, StripLevel::Symbols);
    assert!(!copied_from_release.level.keeps_line_tables());
    assert_eq!(copied_from_release.source, "[profile.dev] strip");

    // The precise one: strip ONLY the debuginfo the profile just asked for.
    let precise = case("[profile.dev]\ndebug = \"line-tables-only\"\nstrip = \"debuginfo\"\n");
    assert!(!precise.level.keeps_line_tables());

    // The glob outranks `[profile.dev]` here as it does for `debug`, so a
    // manifest can look compliant on its first table and not be.
    let outranked = case(
        "[profile.dev]\nstrip = \"none\"\n\n[profile.dev.package.\"*\"]\nstrip = \"symbols\"\n",
    );
    assert!(!outranked.level.keeps_line_tables());
    assert_eq!(outranked.source, "[profile.dev.package.\"*\"] strip");

    // No `strip` at all — today's manifest — resolves to a NAMED default, not a
    // skip, and that default keeps the tables.
    let bare = case("[profile.dev]\ndebug = \"line-tables-only\"\n");
    assert_eq!(bare.level, CARGO_STRIP_DEFAULT);
    assert!(bare.level.keeps_line_tables());
    assert!(bare.source.contains("cargo's built-in dev default"));

    // `strip = false` and `"none"` are the compliant spellings, so the arm is not
    // stuck on "no".
    assert!(
        case("[profile.dev]\nstrip = false\n")
            .level
            .keeps_line_tables()
    );
    assert!(
        case("[profile.dev]\nstrip = \"none\"\n")
            .level
            .keeps_line_tables()
    );

    // Per-spec is swept separately and reds the same way.
    let per_spec: toml::Value =
        toml::from_str("[profile.dev.package.tokio]\nstrip = \"debuginfo\"\n").unwrap();
    let swept = per_package_strip_overrides(&per_spec).expect("sweep");
    assert_eq!(swept, vec![("tokio".to_string(), StripLevel::Debuginfo)]);
    assert!(!swept[0].1.keeps_line_tables());

    // An unrecognised level is an ERROR, not a pass.
    let manifest: toml::Value = toml::from_str("[profile.dev]\nstrip = \"whatever\"\n").unwrap();
    assert!(resolve_dependency_strip(&manifest).is_err());
}

/// A `rustflags` entry that removes debuginfo, if there is one.
///
/// Returns `Some(the offending flag)`. Cargo APPENDS `build.rustflags` /
/// `target.<…>.rustflags` after the flags it derives from the profile, so rustc
/// sees them last and they beat every `[profile.dev]` key
/// [`resolve_dependency_debug`] and [`resolve_dependency_strip`] read.
///
/// Handles the three spellings rustc accepts for a codegen option — `-C k=v`,
/// `-Ck=v` and `--codegen k=v` — because refusing only the tidy one would be a
/// guard an operator defeats by writing the flag the other way.
fn debuginfo_removing_rustflag(flags: &[String]) -> Option<String> {
    let mut pending_key_value: Option<()> = None;
    for (i, flag) in flags.iter().enumerate() {
        let body = if pending_key_value.take().is_some() {
            flag.as_str()
        } else if flag == "-C" || flag == "--codegen" {
            // The value is the NEXT element (`["-C", "debuginfo=0"]`, the form
            // `.cargo/config.toml` arrays are usually written in).
            pending_key_value = Some(());
            continue;
        } else if let Some(rest) = flag.strip_prefix("--codegen=") {
            rest
        } else if let Some(rest) = flag.strip_prefix("-C") {
            rest
        } else {
            continue;
        };
        let body = body.trim();
        let Some((key, value)) = body.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let offending = match key {
            "debuginfo" => !matches!(value, "1" | "2" | "line-tables-only" | "limited" | "full"),
            "strip" => matches!(value, "debuginfo" | "symbols"),
            _ => false,
        };
        if offending {
            // Report the flag as written, including a split `-C` pair, so the
            // failure names something greppable in the file.
            return Some(
                if i > 0 && (flags[i - 1] == "-C" || flags[i - 1] == "--codegen") {
                    format!("{} {}", flags[i - 1], flag)
                } else {
                    flag.clone()
                },
            );
        }
    }
    None
}

/// `rustflags` as cargo accepts it: an array of strings, or one space-separated
/// string.
fn rustflags_of(table: &toml::Value) -> Result<Vec<String>, String> {
    let Some(value) = table.get("rustflags") else {
        return Ok(Vec::new());
    };
    if let Some(s) = value.as_str() {
        return Ok(s.split_whitespace().map(str::to_string).collect());
    }
    let Some(array) = value.as_array() else {
        return Err(format!(
            "rustflags must be an array or a string, got {value}"
        ));
    };
    array
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("rustflags entries must be strings, got {v}"))
        })
        .collect()
}

/// The counterfactual for the RUSTFLAGS arm, on synthetic configs.
///
/// [`cargo_config_declares_no_profile_override`] runs the same classifier against
/// the real `.cargo/config.toml` — which declares no `rustflags` — so without
/// this, that assertion is satisfiable by a classifier that never says yes.
#[test]
fn the_rustflags_classifier_reds_on_flags_that_delete_line_tables() {
    let flags = |text: &str| {
        let config: toml::Value = toml::from_str(text).expect("fixture config parses");
        rustflags_of(config.get("build").expect("[build]")).expect("rustflags parse")
    };

    // The split-pair form, which is how a `.cargo/config.toml` array is usually
    // written.
    assert_eq!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n"))
            .as_deref(),
        Some("-C debuginfo=0")
    );
    // The joined form, and the `none` spelling.
    assert!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = [\"-Cdebuginfo=none\"]\n"))
            .is_some()
    );
    assert!(
        debuginfo_removing_rustflag(&flags(
            "[build]\nrustflags = [\"--codegen\", \"debuginfo=0\"]\n"
        ))
        .is_some()
    );
    // Stripping is the same outcome by a different key.
    assert!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = [\"-Cstrip=debuginfo\"]\n"))
            .is_some()
    );
    assert!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = [\"-C\", \"strip=symbols\"]\n"))
            .is_some()
    );
    // The single-string spelling cargo also accepts.
    assert!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = \"-C debuginfo=0\"\n")).is_some()
    );

    // COMPLIANT flags must pass, or the check is stuck on "no" and would refuse
    // any rustflags at all.
    assert!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = [\"-C\", \"debuginfo=1\"]\n"))
            .is_none()
    );
    assert!(
        debuginfo_removing_rustflag(&flags(
            "[build]\nrustflags = [\"-Cdebuginfo=line-tables-only\"]\n"
        ))
        .is_none()
    );
    assert!(
        debuginfo_removing_rustflag(&flags("[build]\nrustflags = [\"-Cstrip=none\"]\n")).is_none()
    );
    assert!(
        debuginfo_removing_rustflag(&flags(
            "[build]\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n"
        ))
        .is_none()
    );
    assert!(debuginfo_removing_rustflag(&flags("[build]\n")).is_none());
}

/// The manifest resolvers read ONE file. This asserts `.cargo/config.toml`
/// cannot overrule them — by a `[profile.…]` table, or by `rustflags`.
///
/// # Two ways this file beats the manifest, and both are closed here
///
/// * A `[profile.…]` table in a cargo config OUTRANKS the workspace manifest, so
///   a future one would take the refused arm somewhere
///   [`dependency_frames_keep_file_line_under_the_dev_profile`] does not look.
/// * `rustflags` are APPENDED after the flags cargo derives from the profile, so
///   `-C debuginfo=0` or `-C strip=debuginfo` wins over every key that test
///   reads — in the very file it was already parsing.
///
/// The tree's `.cargo/config.toml` sets only `[build] rustc-wrapper` and `jobs`,
/// neither of which touches debuginfo. An absent file overrides nothing, so
/// absence passes too; any other read error, and any parse error, still fails.
///
/// # Why the control is negative
///
/// A positive control on the real file has nothing to observe while the file
/// declares neither table, so it would prove nothing about either predicate.
///
/// The falsifiable control is a NEGATIVE one, run against a synthetic
/// config: the same two predicates asserted below must SAY YES on a file that
/// declares the things they refuse. That is what proves they can fail, and it
/// does not depend on what the real file happens to contain today.
#[test]
fn cargo_config_declares_no_profile_override() {
    let path = repo_root().join(".cargo").join("config.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        // No cargo config in the tree: nothing outranks the manifest.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("reading {}: {e}", path.display()),
    };
    let config: toml::Value =
        toml::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));

    assert!(
        config.get("profile").is_none(),
        "{} now declares a [profile.…] table, which OUTRANKS the root Cargo.toml that \
         `resolve_dependency_debug` reads. Teach the resolver to merge it before landing this, \
         or the line-table rule is enforced against a manifest that no longer decides the \
         build.",
        path.display()
    );

    // `[build] rustflags`, plus every `[target.<cfg>] rustflags` — a target table
    // REPLACES `build.rustflags` for matching units, so checking only `[build]`
    // would leave the same hole open one heading down.
    let mut flag_sources: Vec<(String, &toml::Value)> = Vec::new();
    if let Some(build) = config.get("build") {
        flag_sources.push(("[build]".to_string(), build));
    }
    if let Some(targets) = config.get("target").and_then(toml::Value::as_table) {
        for (cfg, body) in targets {
            flag_sources.push((format!("[target.{cfg:?}]"), body));
        }
    }
    for (heading, table) in flag_sources {
        let flags = rustflags_of(table)
            .unwrap_or_else(|e| panic!("{} {heading} rustflags: {e}", path.display()));
        assert_eq!(
            debuginfo_removing_rustflag(&flags),
            None,
            "{} {heading} rustflags now carries a flag that removes debuginfo. Cargo APPENDS \
             rustflags after the flags it derives from `[profile.dev]`, so rustc sees this LAST \
             and it beats every key `dependency_frames_keep_file_line_under_the_dev_profile` \
             checks — the refused outcome, reached without touching the manifest at all. \
             Flags: {flags:?}",
            path.display(),
        );
    }

    // THE CONTROL, and it is falsifiable: both predicates above must say YES on a
    // config that declares what they refuse. Nothing true of the real (absent)
    // file proves anything about either.
    let hostile: toml::Value = toml::from_str(
        "[profile.dev]\ndebug = false\n\n[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n",
    )
    .expect("control config parses");
    assert!(
        hostile.get("profile").is_some(),
        "the [profile.…] predicate must be able to FIND one, or its absence on the real file is \
         not evidence"
    );
    assert_eq!(
        debuginfo_removing_rustflag(
            &rustflags_of(hostile.get("build").expect("[build]")).expect("control rustflags")
        )
        .as_deref(),
        Some("-C debuginfo=0"),
        "the rustflags predicate must be able to say NO, or its silence on the real file — which \
         the tree does not ship — is not evidence either"
    );
}
