//! The DERIVED cross-face surface inventory, and the derivation
//! guards it makes possible.
//!
//! The inventory covers every command, route, method, resource, tool, and
//! projection across the CLI, MCP, HTTP API, Rust client, and installed
//! skill, each carrying one disposition, guarded so that nothing is falsely
//! advertised — save the pinned rows of `MCP_SERVED_OUTSIDE_THE_API`, the closed
//! list of workstation-local forms MCP serves outside its principal under ADR 0004.
//!
//! **Those faces are not five peers, and the guards here do not pretend they
//! are.** The PRODUCT SURFACE is the Starlark frontend, the `kata` CLI, the API
//! server and the Rust SDK; **MCP is product sugar over the API**, plus the closed,
//! pinned list of workstation-local forms ADR 0004 admits (`author`, `check` of the
//! caller's files, the DSL catalog), and **the installed skill is product sugar over
//! the CLI** (and, as shipped, over MCP — it registers `kata mcp` as its server and
//! teaches that server's tools).
//!
//! Parity is the wrong invariant for a sugar face. It is symmetric, so when a
//! sugar face and its principal disagree it cannot say which one is wrong. The
//! invariant these guards enforce instead is DERIVATION: **a sugar surface may
//! expose less than its principal and never more, and cannot advertise what its
//! principal does not have** — save MCP's pinned workstation-local forms. That is
//! strictly stronger than parity, because it
//! names the authority — and strictly narrower in what it refuses, because a
//! principal carrying something its sugar does not expose is the design rather
//! than debt. See the DERIVATION section at the foot of this file for the
//! refused set (R1-R10) and for
//! `sugar_may_be_a_strict_subset_of_its_principal`, which asserts the
//! non-refusals so the guards cannot be quietly widened back into parity.
//!
//! **The inventory is DERIVED, not written.** A hand-kept table goes stale and
//! nothing notices: a committed inventory that no gate re-runs drifts from the
//! code it describes (method and tool counts that no longer match). Every
//! number in *this* file is recomputed on every run and pinned to a golden, so
//! the same rot is a red test rather than a stale artifact.
//!
//! Per face, the derivation and its authority:
//!
//! | face | kind | rows | derived from |
//! |---|---|---|---|
//! | op-contract (the anchor) | — | operations + request/response fields | `kata_op_contract::Operation::ALL` and `descriptors()` — the schemars schemas themselves |
//! | CLI | principal | every command path, its args, its own `--json` flag | `<kata::cli::Cli as clap::CommandFactory>::command()`, walked |
//! | HTTP API | principal | every method+path pair; which operations `/ops` serves | the axum router-builder bodies in `crates/api/src/**`, resolved through their `nest`/`merge` edges from `ApiServer::build`; a real router over a booted engine, asked each operation (`api_served_operations`) |
//! | Rust client | principal | every public method, and the projection sub-surface | the `pub fn` / `pub async fn` declarations in `crates/client/src/**` |
//! | Starlark | principal | every DSL builtin | `kata_program::dsl_catalog::dsl_catalog()`, itself reflected from the registered `Globals` |
//! | MCP | **sugar over the HTTP API**, plus ADR 0004's pinned workstation-local forms | tools + resources; which calls the default binding serves at the caller | a REAL `kata mcp --no-engine` process, driven over JSON-RPC stdio; a REAL `kata mcp --connect` against a recorded API router (`drive_attached_forms`) |
//! | installed skill | **sugar over the CLI and MCP** | the `kata <cmd>` invocations and the tools the shipped SKILL.md teaches | a REAL `kata skill install --host claude-code --dir <tmp>`, then read back off disk |
//!
//! Two of those are source scans (HTTP routes, client methods) because neither
//! subject can be enumerated any other way: axum 0.8.8's `Router` exposes
//! `has_routes() -> bool` and nothing else — no iteration, no `Debug` that
//! carries paths — and Rust has no stable reflection over a crate's public
//! items. Both scanners therefore carry a COMPLETENESS assertion (see
//! `the_route_scanner_reaches_every_router_builder_in_the_api_crate` and
//! `the_client_scanner_sees_every_public_declaration_in_the_crate`) so a
//! subject the scanner cannot see fails the test instead of silently shrinking
//! the inventory.
//!
//! What is HAND-MAINTAINED here is stated at each site and sized: the
//! disposition of each ABSENT PRINCIPAL-to-PRINCIPAL cell
//! (`ABSENCE_DISPOSITIONS`) and the quarantine of commands whose `--help`
//! advertises `--format` that their dispatch arm never receives
//! (`FORMAT_NEVER_RECEIVED`). Both are pinned by an exact count, so a NEW row
//! cannot join silently and a row whose debt has been paid cannot stay. Sugar-
//! column absences carry no disposition row at all: under derivation they are
//! the design, and a row for each would be the same mechanical answer written
//! out by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcCommand, Stdio};

use clap::CommandFactory as _;
use serde::Serialize;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Workspace paths
// ---------------------------------------------------------------------------

/// `bin/kata` -> the workspace root.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the workspace root")
        .to_path_buf()
}

fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let entries =
            std::fs::read_dir(&next).unwrap_or_else(|e| panic!("read_dir {}: {e}", next.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// A minimal Rust lexer: enough to skip comments and string literals.
// ---------------------------------------------------------------------------

/// Blank out comments while preserving byte offsets inside string literals.
///
/// Nothing here parses Rust. It exists so `.route("/x")` inside a doc comment
/// or a `//`-commented-out line cannot enter the inventory, which is the only
/// way a text scan can lie in the DIRECTION of over-reporting.
fn strip_comments(src: &str) -> String {
    let bytes: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '"' {
            out.push(c);
            i += 1;
            while i < bytes.len() {
                if bytes[i] == '\\' {
                    out.push(bytes[i]);
                    i += 1;
                    if i < bytes.len() {
                        out.push(bytes[i]);
                        i += 1;
                    }
                    continue;
                }
                out.push(bytes[i]);
                let done = bytes[i] == '"';
                i += 1;
                if done {
                    break;
                }
            }
            continue;
        }
        if c == '/' && bytes.get(i + 1) == Some(&'/') {
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && bytes.get(i + 1) == Some(&'*') {
            let mut depth = 1_usize;
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == '/' && bytes.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == '*' && bytes.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Every `fn <name>(..) .. { <body> }` in a comment-stripped source, as
/// `(name, body)`. Declarations without a body (trait signatures) are skipped.
fn fn_bodies(src: &str) -> Vec<(String, String)> {
    let bytes: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if !(bytes[i] == 'f'
            && bytes[i + 1] == 'n'
            && bytes[i + 2].is_whitespace()
            && (i == 0 || !bytes[i - 1].is_alphanumeric() && bytes[i - 1] != '_'))
        {
            i += 1;
            continue;
        }
        let mut j = i + 3;
        while j < bytes.len() && bytes[j].is_whitespace() {
            j += 1;
        }
        let name_start = j;
        while j < bytes.len() && (bytes[j].is_alphanumeric() || bytes[j] == '_') {
            j += 1;
        }
        let name: String = bytes[name_start..j].iter().collect();
        if name.is_empty() {
            i += 1;
            continue;
        }
        // Skip generics + the argument list, then find the body brace.
        while j < bytes.len() && bytes[j] != '(' && bytes[j] != ';' && bytes[j] != '{' {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != '(' {
            i += 1;
            continue;
        }
        let mut depth = 1_usize;
        j += 1;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        while j < bytes.len() && bytes[j] != '{' && bytes[j] != ';' {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] == ';' {
            i += 1;
            continue;
        }
        let body_start = j + 1;
        let mut depth = 1_usize;
        j += 1;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        let body: String = bytes[body_start..j.saturating_sub(1)].iter().collect();
        out.push((name, body));
        i = body_start;
    }
    out
}

/// The argument text of every `.<call>(` in `body`, at any nesting depth.
fn builder_calls(body: &str, call: &str) -> Vec<String> {
    let needle = format!(".{call}(");
    let chars: Vec<char> = body.chars().collect();
    let needle_chars: Vec<char> = needle.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle_chars.len() <= chars.len() {
        if chars[i..i + needle_chars.len()] == needle_chars[..] {
            // `.route(` must not match `.route_service(`: require the char
            // right before `(` to end the call name exactly.
            let start = i + needle_chars.len();
            let mut depth = 1_usize;
            let mut j = start;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            out.push(chars[start..j.saturating_sub(1)].iter().collect());
            i = start;
            continue;
        }
        i += 1;
    }
    out
}

/// The first `"..."` literal in `arg`, if it starts with one.
fn leading_string_literal(arg: &str) -> Option<String> {
    let trimmed = arg.trim_start();
    let rest = trimmed.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---------------------------------------------------------------------------
// FACE: HTTP API — the axum router, resolved from `ApiServer::build`
// ---------------------------------------------------------------------------

const HTTP_METHOD_VERBS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "trace", "any",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct HttpRoute {
    method: String,
    path: String,
    /// The router-builder that registered it, as `<module>::<fn>`.
    registered_by: String,
}

#[derive(Debug, Clone)]
struct RouterDef {
    file: String,
    /// `(path, methods)` from `.route(...)`.
    routes: Vec<(String, Vec<String>)>,
    /// `(prefix, target)` from `.nest(...)`; prefix is `""` for `.merge(...)`.
    mounts: Vec<(String, String)>,
    /// Calls this scanner does NOT model, so the completeness guard can see them.
    unmodelled: Vec<String>,
}

/// Index every router-builder in `crates/api/src/**` by `(module, fn)`.
///
/// `module` is the file stem, except `mod.rs`, which takes its directory's
/// name — so `rest::rest_router` resolves into `rest/mod.rs` and
/// `rest::system::router` into `rest/system.rs`, which is exactly how the
/// call sites spell them.
fn router_defs(root: &Path) -> BTreeMap<(String, String), RouterDef> {
    let mut defs = BTreeMap::new();
    for file in rust_files_under(&root.join("crates/api/src")) {
        let src = strip_comments(
            &std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display())),
        );
        let module = if file.file_name().is_some_and(|n| n == "mod.rs") {
            file.parent()
                .and_then(Path::file_name)
                .expect("mod.rs has a parent directory")
                .to_string_lossy()
                .into_owned()
        } else {
            file.file_stem()
                .expect("rust file has a stem")
                .to_string_lossy()
                .into_owned()
        };
        let rel = file
            .strip_prefix(root)
            .expect("api source under the workspace root")
            .to_string_lossy()
            .into_owned();
        for (name, body) in fn_bodies(&src) {
            let mut routes = Vec::new();
            for arg in builder_calls(&body, "route") {
                let Some(path) = leading_string_literal(&arg) else {
                    continue;
                };
                let after = &arg[arg.find('"').map_or(0, |p| p + path.len() + 2)..];
                routes.push((path, top_level_method_verbs(after)));
            }
            let mut mounts = Vec::new();
            for arg in builder_calls(&body, "nest") {
                let prefix = leading_string_literal(&arg).unwrap_or_default();
                if let Some(target) = builder_target(&arg) {
                    mounts.push((prefix, target));
                }
            }
            for arg in builder_calls(&body, "merge") {
                if let Some(target) = builder_target(&arg) {
                    mounts.push((String::new(), target));
                }
            }
            let mut unmodelled = Vec::new();
            for call in [
                "route_service",
                "nest_service",
                "fallback",
                "fallback_service",
            ] {
                for _ in builder_calls(&body, call) {
                    unmodelled.push(call.to_string());
                }
            }
            if routes.is_empty() && mounts.is_empty() && unmodelled.is_empty() {
                continue;
            }
            defs.insert(
                (module.clone(), name),
                RouterDef {
                    file: rel.clone(),
                    routes,
                    mounts,
                    unmodelled,
                },
            );
        }
    }
    defs
}

/// The HTTP verbs applied at the TOP level of a `.route(path, <here>)`
/// argument — `get(h).post(h)` is two verbs; a `get(` nested inside a
/// handler expression is not one.
fn top_level_method_verbs(after_path: &str) -> Vec<String> {
    let chars: Vec<char> = after_path.chars().collect();
    let mut verbs = Vec::new();
    let mut depth = 0_i32;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if depth == 0 && chars.get(j) == Some(&'(') {
                    let ident: String = chars[start..i].iter().collect();
                    if HTTP_METHOD_VERBS.contains(&ident.as_str()) {
                        verbs.push(ident.to_uppercase());
                    }
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    verbs
}

/// The `a::b::c` in `.merge(a::b::c())` / `.nest("/p", a::b::c())`.
fn builder_target(arg: &str) -> Option<String> {
    let chars: Vec<char> = arg.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == ':')
            {
                i += 1;
            }
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if chars.get(j) == Some(&'(') && chars.get(j + 1) == Some(&')') {
                return Some(chars[start..i].iter().collect());
            }
            continue;
        }
        i += 1;
    }
    None
}

/// Resolve the served route set by walking `nest`/`merge` edges out of
/// `ApiServer::build`. Returns the routes and the set of builders reached.
fn resolve_http_routes(
    defs: &BTreeMap<(String, String), RouterDef>,
) -> (Vec<HttpRoute>, BTreeSet<(String, String)>) {
    let mut routes = BTreeSet::new();
    let mut reached = BTreeSet::new();
    let mut stack = vec![(("server".to_string(), "build".to_string()), String::new())];
    while let Some((key, prefix)) = stack.pop() {
        let Some(def) = defs.get(&key) else {
            panic!(
                "route scanner: `{}::{}` is mounted but no router-builder by that name was \
                 found in crates/api/src. The scanner's module naming (file stem, or the \
                 directory name for mod.rs) no longer matches how the call site spells it.",
                key.0, key.1
            );
        };
        if !reached.insert(key.clone()) {
            continue;
        }
        for (path, verbs) in &def.routes {
            for verb in verbs {
                routes.insert(HttpRoute {
                    method: verb.clone(),
                    path: format!("{prefix}{path}"),
                    registered_by: format!("{}::{}", key.0, key.1),
                });
            }
        }
        for (mount_prefix, target) in &def.mounts {
            let segments: Vec<&str> = target.split("::").collect();
            let module = if segments.len() >= 2 {
                segments[segments.len() - 2].to_string()
            } else {
                key.0.clone()
            };
            let func = (*segments.last().expect("non-empty target")).to_string();
            stack.push(((module, func), format!("{prefix}{mount_prefix}")));
        }
    }
    let mut routes: Vec<HttpRoute> = routes.into_iter().collect();
    routes.sort();
    (routes, reached)
}

// ---------------------------------------------------------------------------
// FACE: CLI — the clap command tree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct CliCommand {
    /// Space-joined path below `kata`, e.g. `run discharge-stop`.
    path: String,
    hidden: bool,
    /// This command declares its own `--json`: a projection that is NOT the
    /// global `--format json` document (`run list`'s NDJSON, `evidence`).
    has_own_json_flag: bool,
    is_leaf: bool,
    args: Vec<String>,
}

fn walk_cli(cmd: &clap::Command, prefix: &[String], out: &mut Vec<CliCommand>) {
    let subs: Vec<&clap::Command> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .collect();
    if !prefix.is_empty() {
        let mut args: Vec<String> = cmd
            .get_arguments()
            .map(|a| a.get_id().as_str().to_string())
            .collect();
        args.sort();
        out.push(CliCommand {
            path: prefix.join(" "),
            hidden: cmd.is_hide_set(),
            has_own_json_flag: cmd
                .get_arguments()
                .any(|a| a.get_id().as_str() == "json" && !a.is_global_set()),
            is_leaf: subs.is_empty(),
            args,
        });
    }
    for sub in subs {
        let mut next = prefix.to_vec();
        next.push(sub.get_name().to_string());
        walk_cli(sub, &next, out);
    }
}

fn cli_commands() -> Vec<CliCommand> {
    let root = kata::cli::Cli::command();
    let mut out = Vec::new();
    walk_cli(&root, &[], &mut out);
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// FACE: MCP — a real `kata mcp --no-engine` over JSON-RPC stdio
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct McpTool {
    name: String,
    input_properties: Vec<String>,
}

/// Drive the shipped binary's MCP face and read back what it ADVERTISES.
///
/// `--no-engine` is the zero-cost mode documented on `run_mcp_cmd`: it boots
/// no engine, opens no attachment, and spends no model budget. Reading the
/// advertisement off the real process rather than off `tools_list()` is what
/// makes this an inventory of the FACE instead of an inventory of a function
/// the face happens to call today.
fn mcp_surface() -> (Vec<McpTool>, Vec<String>) {
    let mut child = ProcCommand::new(env!("CARGO_BIN_EXE_kata"))
        .args(["mcp", "--no-engine"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn `kata mcp --no-engine`");
    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        for frame in [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}),
        ] {
            writeln!(stdin, "{frame}").expect("write JSON-RPC frame");
        }
    }
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .expect("`kata mcp --no-engine` exits when stdin closes");
    let stdout = String::from_utf8(output.stdout).expect("MCP stdout is UTF-8");

    let mut tools = Vec::new();
    let mut resources = Vec::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let frame: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("MCP emitted a non-JSON line {line:?}: {e}"));
        if let Some(list) = frame["result"]["tools"].as_array() {
            for tool in list {
                let mut input_properties: Vec<String> = tool["inputSchema"]["properties"]
                    .as_object()
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default();
                input_properties.sort();
                tools.push(McpTool {
                    name: tool["name"].as_str().expect("tool name").to_string(),
                    input_properties,
                });
            }
        }
        if let Some(list) = frame["result"]["resources"].as_array() {
            for resource in list {
                resources.push(resource["uri"].as_str().expect("resource uri").to_string());
            }
        }
    }
    assert!(
        !tools.is_empty(),
        "inventory: `kata mcp --no-engine` advertised no tools at all — the MCP leg of the \
         inventory would be silently empty. Raw stdout:\n{stdout}"
    );
    tools.sort();
    resources.sort();
    (tools, resources)
}

// ---------------------------------------------------------------------------
// FACE: installed skill — a real `kata skill install`
// ---------------------------------------------------------------------------

/// Install the shipped skill into a scratch directory and return its text.
fn installed_skill_text() -> String {
    let dir = tempfile::tempdir().expect("scratch dir for the skill install");
    let output = ProcCommand::new(env!("CARGO_BIN_EXE_kata"))
        .args(["skill", "install", "--host", "claude-code", "--dir"])
        .arg(dir.path())
        .output()
        .expect("spawn `kata skill install`");
    assert!(
        output.status.success(),
        "`kata skill install --host claude-code` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let skill = dir.path().join(".claude/skills/kata/SKILL.md");
    std::fs::read_to_string(&skill)
        .unwrap_or_else(|e| panic!("read the installed skill at {}: {e}", skill.display()))
}

// ---------------------------------------------------------------------------
// FACE: Rust client — public declarations and the projection sub-surface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct SdkMethod {
    module: String,
    name: String,
}

/// Every `pub fn` / `pub async fn` declared in `crates/client/src/**`.
///
/// This is a declaration scan, not a type-resolved public-API extraction:
/// Rust ships no stable reflection and this workspace has neither
/// `cargo public-api` nor rustdoc-JSON tooling. What the scan CAN prove about itself is that it
/// saw every declaration in the crate; see
/// `the_client_scanner_sees_every_public_declaration_in_the_crate`.
fn sdk_methods(root: &Path) -> Vec<SdkMethod> {
    let src_root = root.join("crates/client/src");
    let mut out = Vec::new();
    for file in rust_files_under(&src_root) {
        let module = file
            .strip_prefix(&src_root)
            .expect("client source under crates/client/src")
            .with_extension("")
            .to_string_lossy()
            .replace('/', "::");
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for line in text.lines() {
            let trimmed = line.trim_start();
            let rest = trimmed
                .strip_prefix("pub async fn ")
                .or_else(|| trimmed.strip_prefix("pub fn "));
            let Some(rest) = rest else { continue };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            out.push(SdkMethod {
                module: module.clone(),
                name,
            });
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The inventory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct OperationRow {
    name: String,
    request_fields: Vec<String>,
    response_fields: Vec<String>,
}

/// One class-A operation's reach across the inventoried faces. Every field
/// is DERIVED; nothing here is a judgement.
///
/// The two `..._names_it` columns match on the operation's own contract NAME,
/// and they are deliberately lists rather than yes/no. Name matching is what
/// an agent or a human actually does when told "call `observe`", so a column
/// that reports the name is absent is reporting the thing that breaks them —
/// and a column that reports FOUR matches is reporting that the contract's
/// word means four different things on that face. Both are findings; neither
/// is an error in the derivation.
// Five independent booleans, one per face, is the SHAPE of a parity matrix.
// The lint's advice — a state machine, or two-variant enums — would replace
// five orthogonal facts with one combined state and lose exactly the
// per-face independence this row exists to record.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct MatrixRow {
    operation: String,
    /// `POST /api/v1/ops/{operation}` exists AND the API, asked through it,
    /// serves this operation — [`api_served_operations`], read off a real
    /// router, not off the contract enum. `false` for an operation the API
    /// answers with its not-served refusal (`author`).
    http_ops_anchor: bool,
    /// Every non-anchor REST route with a path SEGMENT spelling this
    /// operation's name.
    http_routes_whose_path_names_it: Vec<String>,
    /// The MCP `tools/list` advertises a tool with this name.
    mcp_tool: bool,
    /// Every CLI command path whose LAST segment is this operation's contract
    /// name — "can a reader find this operation on the CLI by the name the
    /// contract gives it, and does that name mean only one thing there?"
    cli_commands_whose_last_segment_names_it: Vec<String>,
    /// A CLI call site posts this operation to the `/ops` anchor by literal
    /// name (`invoke_op("<name>"`).
    cli_reaches_the_ops_anchor: bool,
    /// The Rust client declares a `pub fn` with this operation's name.
    sdk_method_named_for_it: bool,
    /// The installed SKILL.md teaches this operation by name.
    skill_teaches_it: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Counts {
    operations: usize,
    cli_commands_total: usize,
    cli_commands_visible: usize,
    cli_commands_leaf_visible: usize,
    cli_commands_with_own_json_flag: usize,
    http_routes: usize,
    http_router_builders: usize,
    mcp_tools: usize,
    mcp_resources: usize,
    sdk_methods: usize,
    sdk_projection_methods: usize,
    starlark_builtins: usize,
    skill_taught_operations: usize,
    /// Operations reachable on the CLI under their own contract name.
    operations_named_on_the_cli: usize,
    /// Operations with a `pub fn` of the same name on the Rust client.
    operations_named_on_the_sdk: usize,
    /// Cells the matrix reports ABSENT between two PRINCIPAL faces — the only
    /// absences that owe a hand-written disposition. Sugar-face absences are
    /// excluded; see [`absent_principal_faces`].
    absent_principal_matrix_cells: usize,
}

/// The sugar-to-principal relation, recorded so the golden carries the shape of
/// the invariant and not only its inputs. Every field is DERIVED.
#[derive(Debug, Clone, Serialize)]
struct Derivation {
    /// The principal MCP derives from.
    mcp_principal: &'static str,
    /// Operations the API's `/ops` anchor serves ([`api_served_operations`])
    /// that MCP does not advertise. A legitimate SUBSET, recorded rather than
    /// dispositioned.
    api_operations_mcp_does_not_advertise: Vec<String>,
    /// The principals the installed skill derives from.
    skill_principals: Vec<&'static str>,
    /// The `kata <cmd>` command paths the installed SKILL.md names.
    skill_named_cli_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Inventory {
    schema_version: u32,
    operations: Vec<OperationRow>,
    cli_commands: Vec<CliCommand>,
    http_routes: Vec<HttpRoute>,
    mcp_tools: Vec<McpTool>,
    mcp_resources: Vec<String>,
    sdk_methods: Vec<SdkMethod>,
    starlark_builtins: Vec<String>,
    skill_taught_operations: Vec<String>,
    matrix: Vec<MatrixRow>,
    derivation: Derivation,
    counts: Counts,
}

/// Operation names a CLI source file posts to the `/ops` anchor by literal
/// name. `bin/kata/src/cli/mcp.rs` proxies `op.as_str()` — a variable,
/// not a literal — so the MCP proxy is deliberately not counted here: this
/// column answers "does the `kata` CLI itself use the anchor", which is the
/// measured 1-of-10 finding.
fn cli_ops_anchor_calls(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for file in rust_files_under(&root.join("bin/kata/src")) {
        let src = strip_comments(
            &std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display())),
        );
        for arg in builder_calls(&src, "invoke_op") {
            if let Some(name) = leading_string_literal(&arg) {
                found.insert(name);
            }
        }
    }
    found
}

fn schema_property_names(schema: &Value) -> Vec<String> {
    let mut names: Vec<String> = schema["properties"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn build_inventory() -> Inventory {
    let root = workspace_root();

    let operations: Vec<OperationRow> = kata_op_contract::descriptors()
        .into_iter()
        .map(|d| OperationRow {
            name: d.name.to_string(),
            request_fields: schema_property_names(&d.request_schema),
            response_fields: schema_property_names(&d.response_schema),
        })
        .collect();

    let cli = cli_commands();
    let defs = router_defs(&root);
    let (http_routes, reached) = resolve_http_routes(&defs);
    let (mcp_tools, mcp_resources) = mcp_surface();
    let sdk = sdk_methods(&root);
    let skill_text = installed_skill_text();
    let anchor_calls = cli_ops_anchor_calls(&root);
    let api_served = api_served_operations();
    let ops_anchor = http_routes
        .iter()
        .any(|r| r.method == "POST" && r.path == "/api/v1/ops/{operation}");

    let mut starlark_builtins: Vec<String> = kata_program::dsl_catalog::dsl_catalog()
        .builtins
        .iter()
        .map(|b| b.name.clone())
        .collect();
    starlark_builtins.sort();

    let mcp_tool_names: BTreeSet<&str> = mcp_tools.iter().map(|t| t.name.as_str()).collect();
    let sdk_names: BTreeSet<&str> = sdk.iter().map(|m| m.name.as_str()).collect();

    let skill_taught_operations: Vec<String> = kata_op_contract::Operation::ALL
        .iter()
        .filter(|op| skill_text.contains(&format!("`{}`", op.as_str())))
        .map(|op| op.as_str().to_string())
        .collect();

    let matrix: Vec<MatrixRow> = kata_op_contract::Operation::ALL
        .iter()
        .map(|op| {
            let name = op.as_str();
            let spelling = name.replace('_', "-");
            let http_named: Vec<String> = http_routes
                .iter()
                .filter(|r| {
                    !r.path.contains("{operation}") && r.path.split('/').any(|seg| seg == spelling)
                })
                .map(|r| format!("{} {}", r.method, r.path))
                .collect();
            let cli_named: Vec<String> = cli
                .iter()
                .filter(|c| !c.hidden)
                .filter(|c| {
                    c.path
                        .rsplit(' ')
                        .next()
                        .is_some_and(|last| last == spelling)
                })
                .map(|c| c.path.clone())
                .collect();
            MatrixRow {
                operation: name.to_string(),
                http_ops_anchor: ops_anchor && api_served.contains(name),
                http_routes_whose_path_names_it: http_named,
                mcp_tool: mcp_tool_names.contains(name),
                cli_commands_whose_last_segment_names_it: cli_named,
                cli_reaches_the_ops_anchor: anchor_calls.contains(name),
                sdk_method_named_for_it: sdk_names.contains(name),
                skill_teaches_it: skill_taught_operations.iter().any(|t| t == name),
            }
        })
        .collect();

    let advertised: BTreeSet<&str> = mcp_tools.iter().map(|t| t.name.as_str()).collect();
    let derivation = Derivation {
        mcp_principal: "http_api",
        api_operations_mcp_does_not_advertise: kata_op_contract::Operation::ALL
            .iter()
            .map(|op| op.as_str().to_string())
            .filter(|name| api_served.contains(name) && !advertised.contains(name.as_str()))
            .collect(),
        skill_principals: vec!["cli", "mcp"],
        skill_named_cli_commands: kata_command_invocations(&skill_text).into_iter().collect(),
    };

    let counts = Counts {
        operations: operations.len(),
        cli_commands_total: cli.len(),
        cli_commands_visible: cli.iter().filter(|c| !c.hidden).count(),
        cli_commands_leaf_visible: cli.iter().filter(|c| !c.hidden && c.is_leaf).count(),
        cli_commands_with_own_json_flag: cli.iter().filter(|c| c.has_own_json_flag).count(),
        http_routes: http_routes.len(),
        http_router_builders: reached.len(),
        mcp_tools: mcp_tools.len(),
        mcp_resources: mcp_resources.len(),
        sdk_methods: sdk.len(),
        sdk_projection_methods: sdk
            .iter()
            .filter(|m| m.module.starts_with("operator_projection"))
            .count(),
        starlark_builtins: starlark_builtins.len(),
        skill_taught_operations: skill_taught_operations.len(),
        operations_named_on_the_cli: matrix
            .iter()
            .filter(|r| !r.cli_commands_whose_last_segment_names_it.is_empty())
            .count(),
        operations_named_on_the_sdk: matrix.iter().filter(|r| r.sdk_method_named_for_it).count(),
        absent_principal_matrix_cells: matrix.iter().map(|r| absent_principal_faces(r).len()).sum(),
    };

    Inventory {
        schema_version: 1,
        operations,
        cli_commands: cli,
        http_routes,
        mcp_tools,
        mcp_resources,
        sdk_methods: sdk,
        starlark_builtins,
        skill_taught_operations,
        matrix,
        derivation,
        counts,
    }
}

/// The PRINCIPAL face columns this matrix row reports as ABSENT, by column
/// name.
///
/// The two SUGAR columns — `mcp_tool` and `skill_teaches_it` — are deliberately
/// NOT reported here and carry no `ABSENCE_DISPOSITIONS` rows. Every sugar
/// absence has the same reason: the operation needs `ApiScope::Approve` and the
/// agent surface holds `Operate`. Hand-written rows restating one mechanical
/// fact are precisely the rot this file exists to delete, and the derivation
/// guards below answer that question — an absent sugar cell is the sugar being
/// a SUBSET of its principal, which is legitimate by definition and owes no
/// judgement. What a sugar face still owes is the other direction, and
/// `mcp_advertises_no_tool_the_api_does_not_serve` /
/// `the_installed_skill_names_nothing_its_principals_do_not_have` refuse it.
///
/// Absence between two PRINCIPAL faces is different in kind: they are peers,
/// so nothing derivable says which one is wrong, and the judgement stays
/// hand-written.
fn absent_principal_faces(row: &MatrixRow) -> Vec<&'static str> {
    let mut out = Vec::new();
    if row.http_routes_whose_path_names_it.is_empty() {
        out.push("http_routes_whose_path_names_it");
    }
    if row.cli_commands_whose_last_segment_names_it.is_empty() {
        out.push("cli_commands_whose_last_segment_names_it");
    }
    if !row.cli_reaches_the_ops_anchor {
        out.push("cli_reaches_the_ops_anchor");
    }
    if !row.sdk_method_named_for_it {
        out.push("sdk_method_named_for_it");
    }
    out
}

// ---------------------------------------------------------------------------
// GOLDEN: the whole inventory, pinned
// ---------------------------------------------------------------------------

const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/goldens/surface_inventory.json"
);

/// The inventory is a checked-in golden, so adding an operation to one face
/// and not another MOVES A NUMBER in a reviewed diff.
///
/// Regenerate intentionally with
/// `UPDATE_SURFACE_INVENTORY_GOLDEN=1 just test-one-crate kata surface_inventory`.
#[test]
fn the_derived_surface_inventory_matches_its_golden() {
    let inventory = build_inventory();
    let mut actual =
        serde_json::to_string_pretty(&inventory).expect("inventory serializes to pretty JSON");
    actual.push('\n');
    if std::env::var_os("UPDATE_SURFACE_INVENTORY_GOLDEN").is_some() {
        std::fs::write(GOLDEN_PATH, &actual).expect("write the surface-inventory golden");
    }
    let expected = std::fs::read_to_string(GOLDEN_PATH).unwrap_or_default();
    if actual == expected {
        return;
    }
    // A 40 KB golden printed twice is not a diff a reader can use; report the
    // differing LINES, capped, plus the count summary that says which face
    // moved.
    let actual_lines: Vec<&str> = actual.lines().collect();
    let expected_lines: Vec<&str> = expected.lines().collect();
    let mut differences = Vec::new();
    for idx in 0..actual_lines.len().max(expected_lines.len()) {
        let got = actual_lines.get(idx).copied().unwrap_or("<end of file>");
        let want = expected_lines.get(idx).copied().unwrap_or("<end of file>");
        if got != want {
            differences.push(format!(
                "  line {}:\n    golden: {want}\n    derived: {got}",
                idx + 1
            ));
        }
        if differences.len() >= 20 {
            differences.push("  ... (truncated at 20 differing lines)".to_string());
            break;
        }
    }
    panic!(
        "inventory: the derived cross-face surface inventory drifted from its golden \
         ({GOLDEN_PATH}).\n{}\n\nIf the change is intended, regenerate with \
         UPDATE_SURFACE_INVENTORY_GOLDEN=1 and review the diff — that diff IS the record of \
         which face gained or lost a command, route, method, resource, tool, or projection.",
        differences.join("\n")
    );
}

// ---------------------------------------------------------------------------
// The scanners must be able to fail
// ---------------------------------------------------------------------------

/// A source scan that quietly sees less than its subject reports a SHRINKING
/// inventory and calls it agreement. Both text scanners therefore assert their
/// own coverage.
#[test]
fn the_route_scanner_reaches_every_router_builder_in_the_api_crate() {
    let root = workspace_root();
    let defs = router_defs(&root);
    let (routes, reached) = resolve_http_routes(&defs);

    let orphans: Vec<String> = defs
        .keys()
        .filter(|k| !reached.contains(*k))
        .map(|(m, f)| format!("{m}::{f}"))
        .collect();
    assert!(
        orphans.is_empty(),
        "inventory: these router-builders register routes that `ApiServer::build` never mounts, so \
         the inventory would either miss them or over-report them: {orphans:?}"
    );

    let unmodelled: Vec<String> = defs
        .iter()
        .filter(|(_, d)| !d.unmodelled.is_empty())
        .map(|((m, f), d)| format!("{m}::{f} uses {:?} ({})", d.unmodelled, d.file))
        .collect();
    assert!(
        unmodelled.is_empty(),
        "inventory: the route scanner models `.route`, `.nest` and `.merge` only. These builders now \
         use a mounting call it does not model, so their routes are invisible to the \
         inventory: {unmodelled:?}"
    );

    // Every `.route(` occurrence in the crate must be one the resolver
    // attributed. Counting the raw occurrences independently is what makes a
    // route added in a file the resolver never walks into a FAILURE.
    let mut raw_sites = 0_usize;
    for file in rust_files_under(&root.join("crates/api/src")) {
        let src = strip_comments(
            &std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display())),
        );
        raw_sites += builder_calls(&src, "route").len();
    }
    let attributed: usize = reached.iter().map(|k| defs[k].routes.len()).sum::<usize>();
    assert_eq!(
        raw_sites, attributed,
        "inventory: crates/api/src contains {raw_sites} `.route(` sites but the resolver attributed \
         {attributed}. A route registered outside a mounted router-builder is served by the \
         product and absent from the inventory."
    );
    assert!(
        routes.iter().any(|r| r.path.ends_with("/ops/{operation}")),
        "inventory: the `/ops` anchor route is the one route the whole op-contract hangs off; the \
         scanner found no route ending in `/ops/{{operation}}`, which means it is broken rather \
         than the route being gone."
    );
}

#[test]
fn the_client_scanner_sees_every_public_declaration_in_the_crate() {
    let root = workspace_root();
    let methods = sdk_methods(&root);
    assert!(
        methods.len() > 50,
        "inventory: the Rust-client scan found only {} public declarations. The client is the \
         richest non-CLI face; a number this low means the scan is broken, not that the face \
         shrank.",
        methods.len()
    );
    // Landmarks the scan MUST find, one per module of the crate, so a scanner
    // that stops after the first file or loses a nested module is VISIBLE
    // rather than merely returning a smaller number.
    for (module, name) in [
        ("client", "invoke_op"),
        ("client", "run_starlark"),
        ("client", "subscribe_event_frames"),
        ("events", "next_frame"),
        ("execution", "wait_for_terminal"),
        ("operator_projection::explain", "explain_summary"),
        ("operator_projection::factory", "factory_candidate_packet"),
        ("operator_projection::report", "execution_report_from_parts"),
        (
            "operator_projection::summaries",
            "run_summary_with_worker_attribution",
        ),
        (
            "operator_projection::worker_attribution",
            "collect_worker_attribution",
        ),
    ] {
        assert!(
            methods.iter().any(|m| m.module == module && m.name == name),
            "inventory: the Rust-client scan lost `{module}::{name}`. Every module of \
             crates/client/src is represented here on purpose: a scan that silently covers \
             fewer files reports a SHRINKING public surface and calls it stability."
        );
    }
}

// ---------------------------------------------------------------------------
// Dispositions: every ABSENT PRINCIPAL-to-PRINCIPAL cell carries one
// ---------------------------------------------------------------------------

/// The dispositions an absent cell may carry ("parity, intentionally
/// face-specific, deprecated, or deleted"; only the first two are in use).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// The absence is DEBT. This cell must reach parity.
    Parity,
    /// The absence is INTENTIONAL. This face does not serve this operation and
    /// is not meant to.
    FaceSpecific,
}

use Disposition::{FaceSpecific, Parity};

/// The ONE hand-maintained table in this file, and the reason it is hand-made
/// is that "should this PRINCIPAL face serve this operation?" is a judgement no
/// derivation can make: the four principals are peers, so nothing decides which
/// of two disagreeing faces is the wrong one.
///
/// It covers principal columns only: [`absent_principal_faces`] does not
/// report the two SUGAR columns, whose absences all share one reason —
/// `ApiScope::Approve` exceeds the agent surface's `Operate` ceiling — which
/// the derivation guards assert mechanically instead of restating by hand.
///
/// [`ABSENCE_DISPOSITION_COUNT`] pins the length, an absent cell with no row
/// FAILS, and a row whose cell is no longer absent FAILS (debt paid, delete
/// the row) rather than lingering as a claim about code that changed.
///
/// `(operation, face column, disposition, reason)`.
const ABSENCE_DISPOSITIONS: &[(&str, &str, Disposition, &str)] = &[
    // ---- author -----------------------------------------------------------
    (
        "author",
        "http_routes_whose_path_names_it",
        FaceSpecific,
        "`author` scaffolds files on the CALLER's workstation. A node has no business writing \
         into a client's checkout, which is why `mcp.rs::remote_invoke` binds `Operation::Author` \
         locally on every binding, as it binds every form that reads the caller's workstation. The `/ops` anchor is its only HTTP surface by \
         design.",
    ),
    (
        "author",
        "cli_commands_whose_last_segment_names_it",
        Parity,
        "The CLI spells this operation `kata init`. One operation, two names — and only the \
         contract's name appears in `tools/list` and SKILL.md, so an agent told to `author` finds \
         no such command and a human reading `kata --help` finds no such operation.",
    ),
    (
        "author",
        "cli_reaches_the_ops_anchor",
        FaceSpecific,
        "Local by construction, so there is no anchor round trip to make. Recorded rather than \
         omitted because the same cell is DEBT for the nine operations below.",
    ),
    (
        "author",
        "sdk_method_named_for_it",
        Parity,
        "The Rust client has no `author` and no scaffolding method at all; an SDK user cannot \
         reach this operation except through the generic `invoke_op`, which would post it to a \
         node that binds it locally anyway.",
    ),
    // ---- check ------------------------------------------------------------
    (
        "check",
        "http_routes_whose_path_names_it",
        FaceSpecific,
        "`check` is served only through the `/ops` anchor; no bespoke route was ever minted for \
         it, so there is nothing here to bring to parity.",
    ),
    (
        "check",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata check` compiles in-process and never touches `/ops`. The cross-face parity harness \
         calls its third leg \"CLI\", but what it drives is the engine-free dispatch — not this \
         command — so nothing observes that these two agree.",
    ),
    (
        "check",
        "sdk_method_named_for_it",
        Parity,
        "The Rust client cannot check a workflow by name. `invoke_op(\"check\", ..)` is the only \
         route, and it is untyped at the call site.",
    ),
    // ---- run --------------------------------------------------------------
    (
        "run",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run <workflow>` posts `/executions` directly, so the CLI's most-used command \
         bypasses the anchor the contract is defined on. This is 1 of the 9 bypasses.",
    ),
    // `run` / `sdk_method_named_for_it` carries no row: the SDK spells it with
    // the contract's word, `run`, plus five argument shapes that do not take the
    // operation's name.
    // ---- observe ----------------------------------------------------------
    (
        "observe",
        "http_routes_whose_path_names_it",
        Parity,
        "`GET /api/v1/executions/{id}` is the bespoke read, and it returns an `ExecutionRecord`, \
         not an `ObserveResponse`. Two projections of one operation, and the path does not carry \
         the operation's name at all.",
    ),
    (
        "observe",
        "cli_commands_whose_last_segment_names_it",
        Parity,
        "There is no `kata observe` and no `kata run observe`, so a script that assumes one \
         reports the absence as a PRODUCT failure.",
    ),
    (
        "observe",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run show` calls `observe` instead of the anchor. 1 of the 9 bypasses.",
    ),
    // `observe` / `sdk_method_named_for_it` carries no row: the SDK spells it
    // with the contract's word. The PAYLOAD divergence — the SDK returns an
    // `ExecutionRecord` where the contract returns an `ObserveResponse` — is not
    // this cell's to record: it is the `observe` /
    // `http_routes_whose_path_names_it` row above, which says the same thing
    // about the bespoke route the SDK calls.
    // ---- list -------------------------------------------------------------
    (
        "list",
        "http_routes_whose_path_names_it",
        Parity,
        "`GET /api/v1/executions` is the bespoke list and returns full records; `ListResponse` is \
         four fields per row. Same operation, two payloads, and the route does not carry the \
         operation's name.",
    ),
    (
        "list",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run list` calls `list` / `list_filtered`. 1 of the 9 bypasses.",
    ),
    // `list` / `sdk_method_named_for_it` carries no row: the SDK spells it with
    // the contract's word. The payload divergence — neither `list` shape returns
    // the contract's `ListResponse` — is recorded on the `list` /
    // `http_routes_whose_path_names_it` row above.
    (
        "approve",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run approve` posts the bespoke `/executions/{id}/approve`. 1 of the 9 bypasses.",
    ),
    (
        "reject",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run reject` posts the bespoke `/executions/{id}/reject`. 1 of the 9 bypasses.",
    ),
    (
        "cancel",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run cancel` posts the bespoke `/executions/{id}/cancel`. 1 of the 9 bypasses.",
    ),
    (
        "promote",
        "cli_reaches_the_ops_anchor",
        Parity,
        "`kata run promote` posts the bespoke `/executions/{id}/promote`. 1 of the 9 bypasses.",
    ),
    // ---- discharge_stop ---------------------------------------------------
    (
        "discharge_stop",
        "http_routes_whose_path_names_it",
        FaceSpecific,
        "It is on the anchor rather than on a bespoke route: the outstanding stop is reported \
         on a projection every face already serves.",
    ),
    (
        "discharge_stop",
        "sdk_method_named_for_it",
        Parity,
        "Reachable only as `invoke_op(\"discharge_stop\", ..)`, so the SDK cannot type the \
         mandatory `operator` and `assertion` fields.",
    ),
    // ---- forge_reconcile --------------------------------------------------
    (
        "forge_reconcile",
        "http_routes_whose_path_names_it",
        FaceSpecific,
        "Born on the anchor: `POST /ops/forge_reconcile` is its only HTTP route, and no bespoke \
         route repeats it.",
    ),
    (
        "forge_reconcile",
        "cli_reaches_the_ops_anchor",
        FaceSpecific,
        "`kata run forge-reconcile` does post `/ops/forge_reconcile`, through the SDK's typed \
         `KataClient::forge_reconcile`; this column scans `bin/kata` for its own `invoke_op` \
         calls, and the CLI calls the SDK's typed method instead of re-decoding the envelope.",
    ),
];

/// Pinned length of [`ABSENCE_DISPOSITIONS`]. A new absence cannot join the
/// table without moving this number in the same diff.
///
/// The SDK spells `run`, `observe` and `list` with `Operation::ALL`'s words, so
/// none of them has an `sdk_method_named_for_it` row. The three that do
/// (`author`, `check`, `discharge_stop`) are operations the SDK
/// does not front at all, which is a coverage question, not a spelling one.
const ABSENCE_DISPOSITION_COUNT: usize = 21;

#[test]
fn every_absent_principal_to_principal_cell_carries_exactly_one_disposition() {
    assert_eq!(
        ABSENCE_DISPOSITIONS.len(),
        ABSENCE_DISPOSITION_COUNT,
        "inventory: ABSENCE_DISPOSITIONS has {} rows and ABSENCE_DISPOSITION_COUNT says {}. The \
         table records real, reviewed judgements; its size is pinned so one cannot be added or \
         dropped without saying so.",
        ABSENCE_DISPOSITIONS.len(),
        ABSENCE_DISPOSITION_COUNT
    );

    let mut keys = BTreeSet::new();
    for (op, face, _, reason) in ABSENCE_DISPOSITIONS {
        assert!(
            keys.insert((*op, *face)),
            "inventory: duplicate disposition for ({op}, {face}) — a cell has exactly one"
        );
        assert!(
            reason.len() > 30,
            "inventory: ({op}, {face}) carries no real reason. A disposition without a reason is a \
             label, and the next reader cannot tell debt from design."
        );
    }

    let inventory = build_inventory();
    let mut missing = Vec::new();
    let mut stale = Vec::new();
    for row in &inventory.matrix {
        let absent: BTreeSet<&str> = absent_principal_faces(row).into_iter().collect();
        for face in &absent {
            if !keys.contains(&(row.operation.as_str(), *face)) {
                missing.push(format!("{} / {face}", row.operation));
            }
        }
        for (op, face) in &keys {
            if *op == row.operation && !absent.contains(face) {
                stale.push(format!("{op} / {face}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "the inventory requires ONE disposition per row. These PRINCIPAL-to-PRINCIPAL cells are ABSENT and \
         undispositioned:\n  {}\nAdd each to ABSENCE_DISPOSITIONS with a reason and bump \
         ABSENCE_DISPOSITION_COUNT.",
        missing.join("\n  ")
    );
    assert!(
        stale.is_empty(),
        "inventory: these cells now have the face they were dispositioned as missing — the debt is \
         PAID and the row must be deleted (and ABSENCE_DISPOSITION_COUNT decremented), not \
         left standing:\n  {}",
        stale.join("\n  ")
    );

    // Non-vacuity: a table of all-`FaceSpecific` would be a way of saying
    // nothing is owed. Both dispositions must actually be used.
    assert!(
        ABSENCE_DISPOSITIONS.iter().any(|r| r.2 == Parity),
        "inventory: no cell is dispositioned `parity`, i.e. the inventory claims the faces owe \
         each other nothing. That is a stronger claim than any measurement here supports."
    );
    assert!(
        ABSENCE_DISPOSITIONS.iter().any(|r| r.2 == FaceSpecific),
        "inventory: no cell is dispositioned `intentionally face-specific`."
    );
}

// ---------------------------------------------------------------------------
// NO FALSE ADVERTISEMENT: `--format` is global, so every command's `--help`
// promises it. Which commands can even receive it?
// ---------------------------------------------------------------------------

/// The set of top-level `Command` variants whose `cli::run` dispatch arm binds
/// the global `format` value, keyed by the clap command name.
///
/// This is a ONE-WAY oracle and that is the point: a command whose arm never
/// receives `format` CANNOT honour `--format json`, whatever its handler does.
/// (The converse is not claimed — `run list` receives it and still emits raw
/// NDJSON by design.) So a violation here is a proof of false advertisement,
/// never a guess at one.
fn commands_that_receive_the_global_format() -> BTreeMap<String, bool> {
    let root = workspace_root();
    let path = root.join("bin/kata/src/cli/mod.rs");
    let src = strip_comments(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    );
    let run_at = src
        .find("pub fn run(cli: Cli)")
        .expect("cli::run is the single CLI dispatch site");
    let match_at = src[run_at..]
        .find("match command {")
        .map(|o| run_at + o)
        .expect("cli::run dispatches on `match command`");
    let chars: Vec<char> = src.chars().collect();
    let open = src[match_at..]
        .find('{')
        .map(|o| src[..match_at + o].chars().count())
        .expect("the match has a body");
    let mut depth = 1_i32;
    let mut i = open + 1;
    while i < chars.len() && depth > 0 {
        match chars[i] {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    let body: String = chars[open + 1..i.saturating_sub(1)].iter().collect();

    // Split at depth-0 `Command::` occurrences: one segment per match arm.
    let body_chars: Vec<char> = body.chars().collect();
    let marker: Vec<char> = "Command::".chars().collect();
    let mut starts = Vec::new();
    let mut depth = 0_i32;
    let mut i = 0;
    while i < body_chars.len() {
        match body_chars[i] {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
        if depth == 0
            && i + marker.len() <= body_chars.len()
            && body_chars[i..i + marker.len()] == marker[..]
        {
            starts.push(i);
            i += marker.len();
            continue;
        }
        i += 1;
    }
    starts.push(body_chars.len());

    let mut out: BTreeMap<String, bool> = BTreeMap::new();
    for window in starts.windows(2) {
        let seg: String = body_chars[window[0]..window[1]].iter().collect();
        let variant: String = seg
            .trim_start_matches("Command::")
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if variant.is_empty() {
            continue;
        }
        // The arm body is everything after the top-level `=>`.
        let seg_chars: Vec<char> = seg.chars().collect();
        let mut depth = 0_i32;
        let mut arrow = None;
        let mut j = 0;
        while j + 1 < seg_chars.len() {
            match seg_chars[j] {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => depth -= 1,
                '=' if depth == 0 && seg_chars[j + 1] == '>' => {
                    arrow = Some(j + 2);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let rhs = arrow.map_or(String::new(), |a| seg_chars[a..].iter().collect());
        let receives = contains_identifier(&rhs, "format");
        let entry = out.entry(pascal_to_clap_name(&variant)).or_insert(false);
        *entry = *entry || receives;
    }
    out
}

fn contains_identifier(haystack: &str, ident: &str) -> bool {
    let chars: Vec<char> = haystack.chars().collect();
    let needle: Vec<char> = ident.chars().collect();
    let mut i = 0;
    while i + needle.len() <= chars.len() {
        if chars[i..i + needle.len()] == needle[..] {
            let before_ok = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
            let after = chars.get(i + needle.len());
            // `!` excluded on purpose: `format!(..)` is the macro, not the
            // global value, and an arm that only formats a string has not
            // received the operator's chosen output format.
            let after_ok = after.is_none_or(|c| !(c.is_alphanumeric() || *c == '_' || *c == '!'));
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `RunSummary` -> `run-summary`, `ApiToken` -> `api-token`. Hidden commands
/// carry an explicit `#[command(name = "__service-exec")]`, whose leading
/// underscores this strips so the two sides of the guard can be compared.
fn pascal_to_clap_name(variant: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in variant.chars().enumerate() {
        if ch.is_uppercase() && idx > 0 {
            out.push('-');
        }
        out.extend(ch.to_lowercase());
    }
    out
}

fn clap_name_key(name: &str) -> String {
    name.trim_start_matches('_').to_string()
}

/// Commands whose `--help` prints `--format <FORMAT>` and whose dispatch arm
/// never receives the value.
///
/// THIS IS DEBT, RECORDED, NOT DESIGN. `--format` is declared
/// `global = true` on `Cli`, so clap prints it in the `Options:` block of
/// every one of these commands' `--help`; none of them can act on it. The
/// class is not hypothetical: a command that accepts `--format json`, prints
/// human prose and exits 0 leaves a scripting caller nothing to branch on.
///
/// The flag's own long help narrows the promise IN PROSE for 13 of these
/// (`status`, `health`, `version`, `workspace`, `execution-workspace`,
/// `workers`, `approvals`, `steer` and the `run` reads) by saying they emit
/// bare records or NDJSON in every format. Prose is not a mechanism, and the
/// remaining rows are not mentioned there at all.
///
/// Sized in the quarantine idiom: a NEW command that advertises a format it
/// never receives FAILS, and a command that starts receiving it must LEAVE
/// this list rather than sit here as a false claim of debt.
const FORMAT_NEVER_RECEIVED: &[(&str, &str)] = &[
    (
        "api-token",
        "mints a token and prints it; no renderer takes an OutputFormat",
    ),
    (
        "approvals",
        "the --format long help calls it NDJSON in every format — prose, not a mechanism",
    ),
    (
        "backup",
        "operator lifecycle command with a human-only report",
    ),
    (
        "config",
        "`config check` prints diagnostics and takes no OutputFormat",
    ),
    (
        "events",
        "an SSE stream renderer; the flag is accepted and dropped",
    ),
    (
        "evidence",
        "`evidence summary`/`list` carry their own --json and never see --format",
    ),
    (
        "execution-workspace",
        "the --format long help calls it a bare record — prose, not a mechanism",
    ),
    (
        "health",
        "the --format long help calls it a bare record — prose, not a mechanism",
    ),
    (
        "init",
        "the CLI spelling of the `author` operation; emits human text only",
    ),
    (
        "login",
        "writes or reports kata's own login files; human text only",
    ),
    (
        "logout",
        "removes kata's own login files and names them; human text only",
    ),
    (
        "mcp",
        "serves JSON-RPC on its own transport; the flag is inert",
    ),
    (
        "memory",
        "four subcommands, none of which takes an OutputFormat",
    ),
    (
        "repair-nucleus",
        "operator recovery command with a human-only report",
    ),
    (
        "replay",
        "a rendered timeline; the flag is accepted and dropped",
    ),
    (
        "restore",
        "operator lifecycle command with a human-only report",
    ),
    (
        "run-summary",
        "a rendered summary; the flag is accepted and dropped",
    ),
    (
        "serve",
        "runs the installed main in the foreground; there is no output projection",
    ),
    (
        "service",
        "seven lifecycle subcommands with human-only reports",
    ),
    (
        "service-exec",
        "hidden service-manager entry point; the flag is inert",
    ),
    (
        "skill",
        "`skill install` reports what it wrote as human text",
    ),
    (
        "status",
        "the --format long help calls it a bare record — prose, not a mechanism",
    ),
    (
        "steer",
        "the --format long help calls it NDJSON in every format — prose, not a mechanism",
    ),
    (
        "syscall-probe",
        "hidden seccomp-floor probe; the flag is inert",
    ),
    (
        "upgrade",
        "operator lifecycle command with a human-only report",
    ),
    (
        "version",
        "the --format long help calls it a bare record — prose, not a mechanism",
    ),
    ("watch", "a live renderer; the flag is accepted and dropped"),
    (
        "workers",
        "the --format long help calls it NDJSON in every format — prose, not a mechanism",
    ),
    (
        "workspace",
        "the --format long help calls it a bare record — prose, not a mechanism",
    ),
];

/// Pinned length of [`FORMAT_NEVER_RECEIVED`].
///
/// A binary that is not `kata` has no `--format` to quarantine, so only
/// `kata` subcommands are counted.
const FORMAT_NEVER_RECEIVED_COUNT: usize = 29;

/// The scanner and clap must agree on the COMMAND SET before the scanner's
/// verdicts mean anything. A parser that silently missed arms would report
/// every missed command as "never receives format" — a guard that fails for
/// the wrong reason, which is the failure mode this repo keeps finding.
#[test]
fn the_dispatch_scanner_sees_exactly_the_commands_clap_declares() {
    let scanned: BTreeSet<String> = commands_that_receive_the_global_format()
        .keys()
        .map(|k| clap_name_key(k))
        .collect();
    let declared: BTreeSet<String> = kata::cli::Cli::command()
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .map(|s| clap_name_key(s.get_name()))
        .collect();
    assert_eq!(
        scanned,
        declared,
        "inventory: the `cli::run` dispatch scanner and clap disagree about which top-level \
         commands exist. Only in `scanned`: {:?}. Only in `declared`: {:?}.",
        scanned.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&scanned).collect::<Vec<_>>(),
    );

    // Positive control: the scanner must find BOTH kinds of arm. If it found
    // no forwarding arm its `format` detection is broken; if it found no
    // dropping arm it cannot see the class it exists for.
    let receives = commands_that_receive_the_global_format();
    assert!(
        receives.values().any(|v| *v),
        "inventory: the scanner says NO command receives the global format — its identifier \
         detection is broken."
    );
    assert!(
        receives.values().any(|v| !*v),
        "inventory: the scanner says EVERY command receives the global format — it cannot see \
         the class it exists for."
    );
}

/// The inventory promises "no false advertisement". This is that
/// clause, mechanised for the one promise every `kata` command makes.
#[test]
fn no_command_advertises_a_format_it_can_never_receive() {
    let root = kata::cli::Cli::command();
    let format_arg = root
        .get_arguments()
        .find(|a| a.get_id().as_str() == "format")
        .expect("`--format` is declared on Cli");
    assert!(
        format_arg.is_global_set(),
        "inventory: this guard's PREMISE is that `--format` is `global = true`, which is what \
         makes every command's `--help` print it. It no longer is, so the promise set must be \
         re-derived rather than this test re-pointed."
    );

    let receives = commands_that_receive_the_global_format();
    let quarantined: BTreeMap<&str, &str> = FORMAT_NEVER_RECEIVED.iter().copied().collect();
    assert_eq!(
        FORMAT_NEVER_RECEIVED.len(),
        FORMAT_NEVER_RECEIVED_COUNT,
        "inventory: FORMAT_NEVER_RECEIVED has {} rows and FORMAT_NEVER_RECEIVED_COUNT says {}.",
        FORMAT_NEVER_RECEIVED.len(),
        FORMAT_NEVER_RECEIVED_COUNT
    );
    assert_eq!(
        quarantined.len(),
        FORMAT_NEVER_RECEIVED.len(),
        "inventory: FORMAT_NEVER_RECEIVED names a command twice"
    );

    let mut undeclared = Vec::new();
    let mut paid = Vec::new();
    for (name, got_format) in &receives {
        let key = clap_name_key(name);
        match (got_format, quarantined.contains_key(key.as_str())) {
            (false, false) => undeclared.push(key),
            (true, true) => paid.push(key),
            _ => {}
        }
    }
    for name in quarantined.keys() {
        assert!(
            receives.contains_key(*name),
            "inventory: FORMAT_NEVER_RECEIVED names `{name}`, which is no longer a `kata` \
             command. Delete the row and decrement FORMAT_NEVER_RECEIVED_COUNT."
        );
    }

    assert!(
        undeclared.is_empty(),
        "no false advertisement: `--format` is declared `global = true`, so these \
         commands PRINT `--format <FORMAT>` in their `--help` while their `cli::run` dispatch \
         arm never receives the value — they cannot honour it, whatever the handler does:\n  \
         {}\nEither forward `format` into the arm, or record the command in \
         FORMAT_NEVER_RECEIVED with a reason and bump FORMAT_NEVER_RECEIVED_COUNT. Recording \
         it is not a fix; it is a debt entry still to pay.",
        undeclared.join("\n  ")
    );
    assert!(
        paid.is_empty(),
        "inventory: these commands NOW receive the global `--format` and are still quarantined as \
         if they could not. Delete their rows and decrement FORMAT_NEVER_RECEIVED_COUNT — a \
         quarantine records real debt only:\n  {}",
        paid.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Headline cross-face facts the inventory exists to keep true
// ---------------------------------------------------------------------------

/// The three counts a reader of the inventory asks for first, asserted against the
/// derivation rather than against prose. These are deliberately EXACT: the
/// point of the inventory is that a face gaining or losing an operation moves
/// a number somebody has to re-state.
#[test]
fn the_inventory_reports_the_measured_cross_face_reach() {
    let inventory = build_inventory();

    assert_eq!(
        inventory.counts.operations, 11,
        "op-contract's closed class-A set"
    );
    assert_eq!(
        inventory.counts.mcp_tools, 5,
        "the MCP surface advertises 5 of the 11 operations under the OPERATE ceiling"
    );
    assert_eq!(
        inventory.counts.operations_named_on_the_sdk, 8,
        "the Rust SDK names 8 of the 11 operations with the contract's own word; the three \
         absent — `author`, `check`, `discharge_stop` — are operations the SDK does not front \
         at all"
    );
    assert_eq!(
        inventory.counts.mcp_resources, 1,
        "the MCP surface advertises ONE resource (the DSL catalog)."
    );
    let anchored = inventory
        .matrix
        .iter()
        .filter(|r| r.cli_reaches_the_ops_anchor)
        .count();
    assert_eq!(
        anchored, 1,
        "the `kata` CLI posts exactly 1 of the 11 operations to the `/ops` anchor itself \
         (`discharge_stop`); `forge_reconcile` reaches it through the SDK's typed method, and \
         the other 9 use bespoke routes or run in-process, so the cross-face parity harness \
         cannot see what the CLI actually does"
    );
    assert!(
        inventory
            .http_routes
            .iter()
            .any(|r| r.path == "/api/v1/ops/{operation}" && r.method == "POST"),
        "the `/ops` anchor is the contract's only uniform HTTP surface"
    );
}

/// The two derived columns that match on the operation's own NAME can be
/// satisfied by a coincidence, and a coincidence read as parity is worse than
/// a recorded absence. These are the cells where the name matches and the
/// contract does not, named so the inventory cannot quietly present them as
/// agreement.
///
/// This assertion is hand-written, and its counterfactual is exact: if any of
/// these collisions is resolved — the agent route renamed, `factory run`
/// renamed, `run list` enveloped — the test fails and the next reader is sent
/// back to this list rather than left with prose that has become false.
#[test]
fn the_cross_face_cells_that_match_by_spelling_only_are_named() {
    let inventory = build_inventory();
    let row = |name: &str| {
        inventory
            .matrix
            .iter()
            .find(|r| r.operation == name)
            .unwrap_or_else(|| panic!("matrix row for `{name}`"))
            .clone()
    };

    // `run`: the only REST paths spelling `run` are the AGENT-run routes, which
    // execute one agent call. The workflow `run` operation submits an
    // execution through `POST /api/v1/executions`, whose path never says `run`.
    assert_eq!(
        row("run").http_routes_whose_path_names_it,
        vec![
            "GET /api/v1/agents/run".to_string(),
            "POST /api/v1/agents/run".to_string()
        ],
        "the HTTP face's `run` is the agent-run route, NOT the `run` operation"
    );
    // `run`: on the CLI the word also names a factory subcommand.
    assert_eq!(
        row("run").cli_commands_whose_last_segment_names_it,
        vec!["factory run".to_string(), "run".to_string()],
        "`run` names two CLI commands"
    );
    // `list`: four CLI commands end in `list`, and the one an operator means
    // emits raw NDJSON records rather than the contract's `ListResponse` —
    // documented on `operator::run::run_list_emits_full_records`.
    assert_eq!(
        row("list").cli_commands_whose_last_segment_names_it,
        vec![
            "evidence list".to_string(),
            "execution-provider list".to_string(),
            "run list".to_string(),
            "workflows list".to_string(),
        ],
        "`list` names four CLI commands, only one of which is the operation"
    );
    // `check`: three commands end in `check`, and only the bare one is the
    // operation the contract means.
    assert_eq!(
        row("check").cli_commands_whose_last_segment_names_it,
        vec![
            "check".to_string(),
            "config check".to_string(),
            "workflows check".to_string(),
        ],
        "`check` names three CLI commands"
    );
}

// ---------------------------------------------------------------------------
// PRINCIPAL: what the HTTP API SERVES, asked of the API
// ---------------------------------------------------------------------------

/// The phrase the API's shared dispatch answers a form it does not serve with:
/// `author` "is a workstation-local operation", and `check` with `all = true` "is a
/// workstation-local operation" (`kata_api::op_dispatch`). Not trusted:
/// [`MCP_SERVED_OUTSIDE_THE_API`]'s probes prove it still matches.
const NOT_SERVED_BY_THE_API_MARKER: &str = "workstation-local";

/// A REAL `ApiServer` router over one booted engine with no worker and an empty
/// library. With `installed`, it answers as an INSTALLED main — the identity `kata
/// mcp`'s attachment verification demands — under that directory id.
///
/// Must be called inside a tokio runtime.
fn probe_api_router(installed: Option<&str>) -> axum::Router {
    use std::sync::Arc;

    let supervisor = Arc::new(kata_transport::WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_millis(500),
    ));
    let dispatcher = Arc::new(kata_workflow::dispatcher::Dispatcher::new(
        Arc::clone(&supervisor),
        heartbeat,
        kata_core::InFlightLedger::in_memory(),
    ));
    let executor = Arc::new(kata_api::executor::WorkflowExecutor::new(
        dispatcher,
        supervisor,
        Arc::new(kata_program::library::WorkflowLibrary::new(vec![])),
    ));
    let health = Arc::new(kata_core::SystemHealth::new());
    health.report(
        kata_core::SubsystemId::Api,
        kata_core::SubsystemHealth::Healthy,
    );
    let mut state = kata_api::state::AppState::with_executor(health, executor);
    if let Some(directory_id) = installed {
        state = state.with_authority_status(kata_api::state::AuthorityStatus {
            process_mode: "installed".to_owned(),
            directory_id: directory_id.to_owned(),
            process_generation: "surface-inventory-generation".to_owned(),
            attachment_protocol_version: kata::attachment::ATTACHMENT_PROTOCOL_VERSION,
            binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            loaded_binary_digest: "surface-inventory-binary".to_owned(),
            control_endpoint: "http://127.0.0.1:0".to_owned(),
            loaded_config_digest: "surface-inventory-config".to_owned(),
            loaded_config_path: "/surface-inventory/kata.toml".to_owned(),
            loaded_service_environment_digest: None,
            recovery_state: "ready".to_owned(),
            next_action: None,
        });
        // What `ApiServer::spawn_on` sets when it serves; this rig serves the router
        // itself, behind its recording layer.
        state.runtime.set_ready(true);
    }
    kata_api::server::ApiServer::build(&kata_test_utils::disabled_auth_config(), state)
        .expect("the API router builds")
        .into_router()
}

/// POST each `(operation, body)` to `/api/v1/ops/{operation}` on a REAL `ApiServer`
/// router over one booted engine, and return each answer's envelope.
///
/// The answer is the API's own, read through its router — never the contract enum
/// (`Operation::ALL`, `descriptors()`), which the MCP surface's `tools/list` is built
/// from too. Asking the enum whether the API serves an operation the enum names is
/// the mirror this replaces.
fn api_ops_answers(requests: &[(&str, Value)]) -> Vec<Value> {
    use tower::ServiceExt as _;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the API probe");
    runtime.block_on(async {
        let router = probe_api_router(None);
        let mut answers = Vec::new();
        for (op, body) in requests {
            let request = axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(format!("/api/v1/ops/{op}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("a probe request");
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("the router answers");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("the answer's body");
            answers.push(
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|e| panic!("/ops/{op} answered a non-JSON body: {e}")),
            );
        }
        answers
    })
}

/// Whether an `/ops` envelope is the API's refusal of a form it does not serve.
fn is_not_served_refusal(envelope: &Value) -> bool {
    envelope["ok"] == false
        && envelope["error"]["code"] == "usage"
        && envelope["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(NOT_SERVED_BY_THE_API_MARKER))
}

/// The operations the HTTP API's `/ops` route SERVES: every contract operation
/// whose answer to an empty request is not the API's not-served refusal.
fn api_served_operations() -> BTreeSet<String> {
    let requests: Vec<(&str, Value)> = kata_op_contract::Operation::ALL
        .iter()
        .map(|op| (op.as_str(), json!({})))
        .collect();
    requests
        .iter()
        .zip(api_ops_answers(&requests))
        .filter(|(_, answer)| !is_not_served_refusal(answer))
        .map(|((name, _), _)| (*name).to_string())
        .collect()
}

/// What `kata mcp` serves that its declared principal, the HTTP API, does NOT: the
/// closed list of workstation-local forms ADR 0004 admits
/// (`docs/architecture/0004-mcp-workstation-local-forms.md`). Each acts only on the
/// caller's own files, through the CLI's own code (`cli::mcp::McpBinding::invoke`):
/// a node can neither scaffold, read nor list a client's files.
///
/// Written out, not derived: each row is an exception to the derivation rule, and an
/// exception must not be derived away. The list is closed — a form joins or leaves
/// only by moving [`MCP_SERVED_OUTSIDE_THE_API_COUNT`] and the ADR — and each row
/// must still be TRUE: a tool or form row's probe must still draw the API's refusal
/// and the attached `kata mcp` must still serve it at the caller, a resource row must
/// still be advertised (R9). Anything else MCP serves outside the API is refused (R7,
/// R8, R10).
///
/// A resource row has no probe, because the API has no resource routes to ask.
const MCP_SERVED_OUTSIDE_THE_API: &[OutsideThePrincipal] = &[
    OutsideThePrincipal {
        kind: "tool",
        name: "author",
        api_probe: Some(("author", "{}")),
        mcp_form: Some(("author", |_| true)),
        why: "project scaffolding: the API answers `author` with its not-served refusal; MCP \
         serves it at the caller on every binding",
    },
    OutsideThePrincipal {
        kind: "form",
        name: "check all=true",
        api_probe: Some(("check", r#"{"all":true}"#)),
        mcp_form: Some(("check", |arguments| arguments["all"] == true)),
        why: "the caller's effective library: the API refuses `all = true`; MCP's `check` \
         inputSchema publishes `all` and serves it at the caller",
    },
    OutsideThePrincipal {
        kind: "form",
        name: "check <path>.star",
        api_probe: Some(("check", r#"{"workflow":"kata-derivation-probe.star"}"#)),
        mcp_form: Some(("check", |arguments| {
            arguments["workflow"].as_str().is_some_and(|workflow| {
                Path::new(workflow)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("star"))
            })
        })),
        why: "a caller's own `.star` file: the API resolves `workflow` only as a library \
         name and refuses a path it cannot read; MCP reads the file and checks it at the \
         caller, as `kata check <path>` does",
    },
    OutsideThePrincipal {
        kind: "resource",
        name: "kata://workflows/dsl-catalog",
        api_probe: None,
        mcp_form: None,
        why: "the workflow DSL catalog: no `/api/v1/**` route returns it; it is the CLI's \
         `kata workflows schema`",
    },
];

/// One row of [`MCP_SERVED_OUTSIDE_THE_API`].
struct OutsideThePrincipal {
    /// `tool`, `form` (an argument form of an advertised tool) or `resource`.
    kind: &'static str,
    /// The tool, the form, or the resource URI.
    name: &'static str,
    /// The `(operation, body)` the API must still refuse (`ok: false`).
    api_probe: Option<(&'static str, &'static str)>,
    /// The `(tool, arguments predicate)` that recognises this row's calls among
    /// the forms R10 drives: a call it matches may be served at the caller, and
    /// at least one must be (R9).
    mcp_form: Option<McpForm>,
    /// Why MCP serves it.
    why: &'static str,
}

/// A row's MCP form: the tool, and the predicate its call's arguments must meet.
type McpForm = (&'static str, fn(&Value) -> bool);

impl OutsideThePrincipal {
    /// Whether this row excuses `tool` called with `arguments`.
    fn excuses(&self, tool: &str, arguments: &Value) -> bool {
        self.mcp_form
            .is_some_and(|(row_tool, matches)| row_tool == tool && matches(arguments))
    }
}

/// Pinned length of [`MCP_SERVED_OUTSIDE_THE_API`].
const MCP_SERVED_OUTSIDE_THE_API_COUNT: usize = 4;

// ---------------------------------------------------------------------------
// DERIVATION: each sugar surface derives from its principal
// ---------------------------------------------------------------------------
//
// The four PRINCIPAL faces (Starlark, CLI, HTTP API, Rust SDK) are peers: an
// absence between two of them is a judgement, which is why
// `ABSENCE_DISPOSITIONS` above is hand-written and why it is the only
// hand-written table left in this file.
//
// The two SUGAR faces are not peers, and these guards are the whole
// difference. MCP is sugar over the HTTP API; the installed skill is sugar
// over the CLI and over MCP. A parity check between a sugar face and its
// principal is symmetric and therefore cannot say which side is wrong when
// the two disagree. Derivation names the authority: the sugar may expose LESS
// than its principal and never MORE — save the closed list of workstation-local
// forms ADR 0004 admits for MCP, the rows of `MCP_SERVED_OUTSIDE_THE_API` — so a
// disagreement outside that list has exactly one guilty party, the sugar, and
// the guard can say so.
//
// What this REFUSES, and nothing else:
//
//   R1  an MCP `tools/list` entry whose name is not a class-A operation
//   R2  an MCP tool whose `inputSchema` properties differ from the operation's
//       request-schema properties
//   R3  an MCP tool the running server refuses at call time under its own
//       capability ceiling (advertised, not callable)
//   R4  the disappearance of `POST /api/v1/ops/{operation}`, which is the
//       premise every MCP tool derives through
//   R5  a backticked `kata <cmd>` span in the installed SKILL.md that resolves
//       to no visible CLI command path
//   R6  a backticked bare operation name in the installed SKILL.md that the
//       running MCP server does not advertise
//   R7  an MCP tool whose operation the API, asked through its own router,
//       answers with its not-served refusal — unless a `tool` row of
//       `MCP_SERVED_OUTSIDE_THE_API` names it
//   R8  an MCP resource no `resource` row of `MCP_SERVED_OUTSIDE_THE_API` names
//       (the API serves no resource, so every one is outside it)
//   R9  a row of `MCP_SERVED_OUTSIDE_THE_API` that is no longer true: its probe
//       is answered `ok` by the API, its form is no longer served at the caller by
//       the attached `kata mcp`, or its resource is no longer advertised — and a
//       row count other than `MCP_SERVED_OUTSIDE_THE_API_COUNT`
//   R10 a call the DEFAULT (attached) `kata mcp` answers with a success while
//       putting no request on the API, unless a row of `MCP_SERVED_OUTSIDE_THE_API`
//       matches it — over the corpus `generated_form_corpus` builds from every
//       advertised tool's own `inputSchema`
//
// R1 and R2 read the CONTRACT (`descriptors()`), which `tools/list` is built from:
// they prove a tool is SOME operation with that operation's schema, not that the
// API serves it. R7-R10 are the ones that ask the API: R7 and R9's probes through its
// router, R10 and R9's form half by recording what reached it. NOT refused, by any
// guard here: a form served at the caller only for an argument value the corpus does
// not generate (`the_attached_mcp_serves_at_the_caller_only_its_pinned_forms` states
// the bound); a resource served by `resources/read` that `resources/list` does not
// advertise, and any other JSON-RPC method (R8 reads the listing only); and
// `kata mcp --no-engine`, which binds no API at all, serving `check`
// by library name against the caller's library. A `run` of a `.star` PATH is not
// outside the API: MCP reads the file and submits it as the inline
// `workflow_starlark` the API serves, and R10 sees that request reach the API.
//
// What this deliberately does NOT refuse, asserted directly in
// `sugar_may_be_a_strict_subset_of_its_principal`: a principal carrying
// something its sugar does not expose. Every operation above MCP's OPERATE
// ceiling is served by the API and absent from MCP; all but two of the visible CLI
// commands are never named by the skill. Both are the design, not debt, and a
// guard that reddened on either would be a parity check wearing a new name.

/// The distinctive phrase in the `kata mcp` capability-ceiling refusal
/// (`cli::mcp::scope_ceiling::OperatePermitted::check`).
///
/// R3 keys on this rather than on an error code because the ceiling refusal
/// and an ordinary bad-arguments refusal are both `usage`. The marker is not
/// trusted: `mcp_advertises_no_tool_the_api_does_not_serve` proves it still
/// matches by probing operations the surface is KNOWN to refuse, and fails if
/// those probes come back unmarked.
const CEILING_REFUSAL_MARKER: &str = "is OPERATE-only";

/// `tools/call` every named tool on a real `kata mcp --no-engine` and return
/// `name -> error message` (empty string when the call did not error).
///
/// `arguments` is deliberately a STRING, not an object. The capability ceiling
/// is checked before the arguments are deserialized
/// (`McpBinding::invoke` calls `OperatePermitted::check` and only then
/// `dispatch`), so a payload that cannot deserialize into any request still
/// reveals the ceiling verdict — while making it impossible for the probe to
/// reach a binding and cause an effect. Measured: with a string payload
/// `author` stops at "expected struct AuthorRequest" and scaffolds nothing.
fn mcp_call_probe(names: &[String]) -> BTreeMap<String, String> {
    let mut child = ProcCommand::new(env!("CARGO_BIN_EXE_kata"))
        .args(["mcp", "--no-engine"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn `kata mcp --no-engine`");
    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}})
        )
        .expect("write initialize");
        for (idx, name) in names.iter().enumerate() {
            let frame = json!({
                "jsonrpc": "2.0",
                "id": idx + 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": "kata-derivation-probe"},
            });
            writeln!(stdin, "{frame}").expect("write tools/call frame");
        }
    }
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .expect("`kata mcp --no-engine` exits when stdin closes");
    let stdout = String::from_utf8(output.stdout).expect("MCP stdout is UTF-8");

    let mut out = BTreeMap::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let frame: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("MCP emitted a non-JSON line {line:?}: {e}"));
        let Some(id) = frame["id"].as_u64() else {
            continue;
        };
        if id == 0 {
            continue;
        }
        let name = names
            .get(usize::try_from(id - 1).expect("probe id fits usize"))
            .unwrap_or_else(|| panic!("MCP answered id {id} with no matching request"));
        let message = frame["error"]["message"].as_str().unwrap_or("").to_string();
        out.insert(name.clone(), message);
    }
    assert_eq!(
        out.len(),
        names.len(),
        "the MCP server answered {} of {} probe calls; the probe cannot report on a tool it \
         never heard back about.\nraw stdout:\n{stdout}",
        out.len(),
        names.len()
    );
    out
}

/// Every backticked span in `text`.
fn backticked_spans(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        rest = &rest[open + 1..];
        let Some(close) = rest.find('`') else { break };
        out.push(rest[..close].to_string());
        rest = &rest[close + 1..];
    }
    out
}

/// The `kata <cmd>` invocations a document names, as command paths below
/// `kata`.
///
/// Only the leading run of COMMAND-SHAPED tokens is kept, so a span like
/// `` `kata workflows check --all` `` yields `workflows check`: everything
/// from the first flag or placeholder on is an argument, not a command path.
/// A span that is merely `` `kata` ``, or whose first token is a flag, names
/// no command and is not reported — and neither is `` `kata.toml` ``, which
/// does not carry the trailing space.
fn kata_command_invocations(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for span in backticked_spans(text) {
        let Some(tail) = span.strip_prefix("kata ") else {
            continue;
        };
        let path: Vec<&str> = tail
            .split_whitespace()
            .take_while(|t| {
                t.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && t.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
            .collect();
        if !path.is_empty() {
            out.insert(path.join(" "));
        }
    }
    out
}

/// The longest prefix of `invocation` that is a visible CLI command path.
///
/// Backing off from the right is required, not a convenience: `kata run
/// my-pack` names the `run` command and then its positional argument, and a
/// positional argument is not a missing subcommand.
fn longest_cli_prefix(invocation: &str, visible: &BTreeSet<String>) -> Option<String> {
    let tokens: Vec<&str> = invocation.split(' ').collect();
    (1..=tokens.len())
        .rev()
        .map(|n| tokens[..n].join(" "))
        .find(|candidate| visible.contains(candidate))
}

/// R1-R4, R7, R8 and R9's probe and resource halves. The MCP face is sugar over
/// the HTTP API's operation set:
/// every tool it advertises must be a contract operation (R1) carrying that
/// operation's own request schema (R2), callable on the surface that listed it
/// (R3), and SERVED by the API when the API is asked (R7) — save the rows of
/// [`MCP_SERVED_OUTSIDE_THE_API`], each of which must still be true (R9); and
/// every resource it advertises is one of those rows (R8).
#[test]
fn mcp_advertises_no_tool_the_api_does_not_serve() {
    let root = workspace_root();
    let (mcp_tools, _) = mcp_surface();
    let defs = router_defs(&root);
    let (http_routes, _) = resolve_http_routes(&defs);

    // R4 — the premise. Every MCP tool reaches its operation through this one
    // route (`cli::mcp::remote_invoke` POSTs `op.as_str()` to it); without the
    // anchor the MCP face is not sugar over anything and this guard is vacuous.
    assert!(
        http_routes
            .iter()
            .any(|r| r.method == "POST" && r.path == "/api/v1/ops/{operation}"),
        "DERIVATION (R4): `POST /api/v1/ops/{{operation}}` is gone. Every MCP tool derives from \
         the API's operation set through that anchor; with the anchor deleted there is no \
         principal for the sugar to derive from."
    );

    let descriptors = kata_op_contract::descriptors();
    let by_name: BTreeMap<&str, &kata_op_contract::OpDescriptor> =
        descriptors.iter().map(|d| (d.name, d)).collect();

    let mut orphans = Vec::new();
    let mut schema_drift = Vec::new();
    for tool in &mcp_tools {
        // R1 — a tool with no operation behind it.
        let Some(descriptor) = by_name.get(tool.name.as_str()) else {
            orphans.push(tool.name.clone());
            continue;
        };
        // R2 — a tool that advertises arguments the operation does not accept.
        //
        // The refused set is PROPERTY NAMES, not the whole schema: a type or a
        // required-ness drift passes this check. That bound is deliberate and it is
        // cheap to hold because `tools_list` embeds `descriptor.request_schema`
        // VERBATIM, so any drift at all takes a hand-edit — R2 is belt-and-braces
        // over a derivation that is already by-construction. Widening it to a full
        // structural compare would be strictly better and is not free; if this ever
        // stops embedding the schema verbatim, widen it before that lands.
        let contract_fields = schema_property_names(&descriptor.request_schema);
        if contract_fields != tool.input_properties {
            schema_drift.push(format!(
                "{}: the tool advertises the properties {:?}, the operation's request schema declares {:?}",
                tool.name, tool.input_properties, contract_fields
            ));
        }
    }
    assert!(
        orphans.is_empty(),
        "DERIVATION (R1): the MCP face advertises tools with no API operation behind them: \
         {orphans:?}.\nMCP is sugar over the HTTP API — `tools/list` is `descriptors()` filtered \
         by the surface's own capability ceiling. A name that is not a class-A operation cannot \
         be proxied to `POST /api/v1/ops/{{operation}}`, so the tool advertises a capability the \
         product does not have."
    );
    assert!(
        schema_drift.is_empty(),
        "DERIVATION (R2): the MCP face advertises an inputSchema that is not the operation's \
         request schema:\n  {}\nThe tool's schema must BE the contract's, not merely agree with \
         it — an agent fills the advertised fields and the API decodes the contract's.",
        schema_drift.join("\n  ")
    );

    // R7-R9 — ask the API, through its own router, whether it serves what MCP
    // advertises.
    assert_eq!(
        MCP_SERVED_OUTSIDE_THE_API.len(),
        MCP_SERVED_OUTSIDE_THE_API_COUNT,
        "DERIVATION (R9): MCP_SERVED_OUTSIDE_THE_API has {} rows and its pinned count says {}. \
         A divergence from the principal rule joins or leaves only by moving that number.",
        MCP_SERVED_OUTSIDE_THE_API.len(),
        MCP_SERVED_OUTSIDE_THE_API_COUNT
    );
    let api_served = api_served_operations();
    let excepted_tools: BTreeSet<&str> = MCP_SERVED_OUTSIDE_THE_API
        .iter()
        .filter(|row| row.kind == "tool")
        .map(|row| row.name)
        .collect();
    let unserved: Vec<&String> = mcp_tools
        .iter()
        .map(|tool| &tool.name)
        .filter(|name| !api_served.contains(*name) && !excepted_tools.contains(name.as_str()))
        .collect();
    assert!(
        unserved.is_empty(),
        "DERIVATION (R7): the MCP face advertises tools the HTTP API does not serve: \
         {unserved:?}. Asked through its own router, the API answers each with its \
         not-served refusal ({NOT_SERVED_BY_THE_API_MARKER:?}). MCP derives from the API; \
         a tool the API refuses is served from somewhere else."
    );
    let excepted_resources: BTreeSet<&str> = MCP_SERVED_OUTSIDE_THE_API
        .iter()
        .filter(|row| row.kind == "resource")
        .map(|row| row.name)
        .collect();
    let (_, mcp_resources) = mcp_surface();
    let unlisted: Vec<&String> = mcp_resources
        .iter()
        .filter(|uri| !excepted_resources.contains(uri.as_str()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "DERIVATION (R8): the MCP face advertises resources the HTTP API does not serve: \
         {unlisted:?}. The API has no resource routes, so every MCP resource is served \
         outside its principal and must be a row of MCP_SERVED_OUTSIDE_THE_API."
    );
    let probe_rows: Vec<&OutsideThePrincipal> = MCP_SERVED_OUTSIDE_THE_API
        .iter()
        .filter(|row| row.api_probe.is_some())
        .collect();
    let probes: Vec<(&str, Value)> = probe_rows
        .iter()
        .filter_map(|row| row.api_probe)
        .map(|(op, body)| {
            (
                op,
                serde_json::from_str(body).expect("a probe body is JSON"),
            )
        })
        .collect();
    let probe_answers = api_ops_answers(&probes);
    let mut stale = Vec::new();
    for ((row, (op, body)), answer) in probe_rows.iter().zip(&probes).zip(&probe_answers) {
        if answer["ok"] != false {
            stale.push(format!(
                "{} {} ({}): /ops/{op} {body} answered {answer}",
                row.kind, row.name, row.why
            ));
        }
    }
    for row in MCP_SERVED_OUTSIDE_THE_API
        .iter()
        .filter(|row| row.kind == "resource")
    {
        if !mcp_resources
            .iter()
            .any(|advertised| advertised == row.name)
        {
            stale.push(format!(
                "resource {} ({}) is no longer advertised",
                row.name, row.why
            ));
        }
    }
    assert!(
        stale.is_empty(),
        "DERIVATION (R9): rows of MCP_SERVED_OUTSIDE_THE_API that are no longer true:\n  {}\n\
         A row records a divergence from the principal rule; once the API serves it or MCP \
         drops it, the row must go.",
        stale.join("\n  ")
    );
    assert!(
        probe_answers.iter().any(is_not_served_refusal),
        "DERIVATION (R7/R9) is VACUOUS: no probe drew the not-served refusal \
         {NOT_SERVED_BY_THE_API_MARKER:?}; the marker no longer matches the API's answer"
    );

    // R3 — advertised must mean callable. Probe the real server: every
    // advertised tool, plus every operation it does NOT advertise as the
    // control that proves the probe can still see a ceiling refusal.
    let advertised: BTreeSet<String> = mcp_tools.iter().map(|t| t.name.clone()).collect();
    let unadvertised: Vec<String> = kata_op_contract::Operation::ALL
        .iter()
        .map(|op| op.as_str().to_string())
        .filter(|name| !advertised.contains(name))
        .collect();
    let mut probe_names: Vec<String> = advertised.iter().cloned().collect();
    probe_names.extend(unadvertised.iter().cloned());
    let verdicts = mcp_call_probe(&probe_names);

    let refused: Vec<String> = advertised
        .iter()
        .filter(|name| verdicts[*name].contains(CEILING_REFUSAL_MARKER))
        .cloned()
        .collect();
    assert!(
        refused.is_empty(),
        "DERIVATION (R3): the MCP face ADVERTISES tools its own capability ceiling REFUSES: \
         {refused:?}. Advertised and callable are meant to be the same boolean \
         (`cli::mcp::surface_permits`, read once by `tools_list` and once by \
         `OperatePermitted::check`); an agent that believes `tools/list` is being lied to."
    );
    let control_seen: Vec<&String> = unadvertised
        .iter()
        .filter(|name| verdicts[*name].contains(CEILING_REFUSAL_MARKER))
        .collect();
    assert!(
        !control_seen.is_empty(),
        "DERIVATION (R3) is VACUOUS: not one of the {} unadvertised operations came back with \
         the ceiling refusal marker {CEILING_REFUSAL_MARKER:?}, so the assertion above cannot \
         see the thing it claims to refuse. Verdicts: {verdicts:?}",
        unadvertised.len()
    );
}

/// Every advertised tool's `inputSchema`, read off a real `kata mcp --no-engine`'s
/// `tools/list`.
fn mcp_tool_input_schemas() -> BTreeMap<String, Value> {
    let mut child = ProcCommand::new(env!("CARGO_BIN_EXE_kata"))
        .args(["mcp", "--no-engine"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn `kata mcp --no-engine`");
    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        for frame in [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        ] {
            writeln!(stdin, "{frame}").expect("write JSON-RPC frame");
        }
    }
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .expect("`kata mcp --no-engine` exits when stdin closes");
    let stdout = String::from_utf8(output.stdout).expect("MCP stdout is UTF-8");
    let mut schemas = BTreeMap::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let frame: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("MCP emitted a non-JSON line {line:?}: {e}"));
        for tool in frame["result"]["tools"].as_array().into_iter().flatten() {
            schemas.insert(
                tool["name"].as_str().expect("tool name").to_string(),
                tool["inputSchema"].clone(),
            );
        }
    }
    assert!(
        !schemas.is_empty(),
        "tools/list advertised nothing:\n{stdout}"
    );
    schemas
}

/// The values R10 tries for one property `schema` (inside the tool's `root` schema):
/// both booleans, `1`, an empty array or object, and for a string a name no library
/// holds, [`CALLER_LIBRARY_NAME`] — a name the caller's own library resolves — and the
/// path of an existing `.star` file: the shapes a caller's workflow argument takes,
/// with a name that `check` could serve at the caller by resolving it there. A `$ref`
/// resolves in `root`; a union contributes each member's values.
fn sample_values(root: &Value, schema: &Value, star_path: &str) -> Vec<Value> {
    if let Some(reference) = schema["$ref"].as_str() {
        let name = reference
            .rsplit('/')
            .next()
            .expect("a $ref names a definition");
        let target = root["$defs"]
            .get(name)
            .or_else(|| root["definitions"].get(name))
            .unwrap_or_else(|| panic!("{reference} resolves in the tool's schema"));
        return sample_values(root, target, star_path);
    }
    if let Some(first) = schema["enum"].as_array().and_then(|values| values.first()) {
        return vec![first.clone()];
    }
    if let Some(constant) = schema.get("const") {
        return vec![constant.clone()];
    }
    let mut out = Vec::new();
    for union in ["anyOf", "oneOf", "allOf"] {
        for member in schema[union].as_array().into_iter().flatten() {
            out.extend(sample_values(root, member, star_path));
        }
    }
    let types: Vec<&str> = match &schema["type"] {
        Value::String(one) => vec![one.as_str()],
        Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    for ty in types {
        match ty {
            "boolean" => out.extend([json!(true), json!(false)]),
            "integer" | "number" => out.push(json!(1)),
            "string" => out.extend([
                json!("kata-derivation-probe"),
                json!(CALLER_LIBRARY_NAME),
                json!(star_path),
            ]),
            "array" => out.push(json!([])),
            "object" => out.push(json!({})),
            _ => {}
        }
    }
    out.retain(|value| !value.is_null());
    out.dedup();
    out
}

/// A workflow the caller's effective library resolves by name: the shipped standard
/// library's `workflows/std/kata-loop-lite.star`, which an attached `kata mcp` with no
/// project library of its own reads. A `check` of it that a change served at the
/// caller, resolving the name there, would succeed with no request on the API — the
/// form R10 must then see — where a name no library holds fails either way.
const CALLER_LIBRARY_NAME: &str = "kata-loop-lite";

/// R10's corpus, GENERATED from each advertised tool's own `inputSchema`: per tool, a
/// base call carrying every required property at its first sample value, then the base
/// with each property in turn set to each of its [`sample_values`]. Nothing here names
/// a tool or a property, so a new tool, property or property type joins the corpus
/// without an edit.
fn generated_form_corpus(
    schemas: &BTreeMap<String, Value>,
    star_path: &str,
) -> Vec<(String, Value)> {
    let mut corpus = Vec::new();
    for (tool, schema) in schemas {
        let properties = schema["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        let mut base = serde_json::Map::new();
        for required in schema["required"].as_array().into_iter().flatten() {
            let name = required.as_str().expect("a required property name");
            let value = sample_values(schema, &properties[name], star_path)
                .into_iter()
                .next()
                .unwrap_or_else(|| {
                    panic!("{tool}.{name}: no sample value for a required property")
                });
            base.insert(name.to_string(), value);
        }
        let mut forms = vec![Value::Object(base.clone())];
        for (name, property) in &properties {
            for value in sample_values(schema, property, star_path) {
                let mut form = base.clone();
                form.insert(name.clone(), value);
                forms.push(Value::Object(form));
            }
        }
        forms.dedup();
        corpus.extend(forms.into_iter().map(|form| (tool.clone(), form)));
    }
    corpus
}

/// One R10 call's outcome on the attached `kata mcp`.
struct AttachedOutcome {
    /// The call answered a success envelope.
    ok: bool,
    /// The call put at least one request on the API while it was being answered.
    reached_the_api: bool,
    /// The raw answer frame.
    frame: Value,
}

/// The execution id R10's `n`th marker `observe` carries: 26 digits, a valid ULID
/// spelling that no corpus form uses.
fn marker_execution_id(n: usize) -> String {
    format!("{n:026}")
}

/// Drive the REAL default `kata mcp` — attached with `--connect` to a real API router
/// served on loopback, every request it receives recorded by a layer in front of it —
/// through `corpus`, and say for each call whether it was answered and whether it
/// reached the API.
///
/// The server answers one request before it reads the next, so a call's requests are
/// the ones recorded between the `observe` markers sent around it. A marker is itself
/// a proxied call; if `observe` stopped reaching the API the markers would vanish and
/// the count assertion here fails rather than letting every call read as local.
fn drive_attached_forms(project: &Path, corpus: &[(String, Value)]) -> Vec<AttachedOutcome> {
    use std::sync::{Arc, Mutex};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime for the attached rig");
    let seen: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    let frames = runtime.block_on(async {
        let recorder = {
            let seen = Arc::clone(&seen);
            axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let seen = Arc::clone(&seen);
                    async move {
                        let (parts, body) = request.into_parts();
                        let bytes = axum::body::to_bytes(body, usize::MAX)
                            .await
                            .expect("a recorded request's body");
                        let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        seen.lock()
                            .expect("the recorder lock")
                            .push((parts.uri.path().to_string(), parsed));
                        next.run(axum::extract::Request::from_parts(
                            parts,
                            axum::body::Body::from(bytes),
                        ))
                        .await
                    }
                },
            )
        };
        let router = probe_api_router(Some("surface-inventory-directory")).layer(recorder);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let server = tokio::spawn(async move { axum::serve(listener, router).await });

        let mut requests = vec![json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}})];
        let marker = |n: usize| {
            json!({"jsonrpc":"2.0","id":format!("marker-{n}"),"method":"tools/call",
                "params":{"name":"observe","arguments":{"execution_id":marker_execution_id(n)}}})
        };
        requests.push(marker(0));
        for (index, (tool, arguments)) in corpus.iter().enumerate() {
            requests.push(
                json!({"jsonrpc":"2.0","id":format!("form-{index}"),"method":"tools/call",
                "params":{"name":tool,"arguments":arguments}}),
            );
            requests.push(marker(index + 1));
        }
        let project = project.to_path_buf();
        let frames = tokio::task::spawn_blocking(move || {
            let mut child = ProcCommand::new(env!("CARGO_BIN_EXE_kata"))
                .args(["mcp", "--connect", &url])
                .current_dir(&project)
                .env("HOME", &project)
                .env_remove("KATA_API_TOKEN")
                .env_remove("KATA_API_URL")
                .env_remove("KATA_CONFIG")
                .env_remove("KATA_STDLIB_DIR")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn `kata mcp --connect`");
            {
                let mut stdin = child.stdin.take().expect("child stdin");
                for request in &requests {
                    writeln!(stdin, "{request}").expect("write request line");
                }
            }
            let output = child.wait_with_output().expect("wait for `kata mcp`");
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                output.status.success(),
                "`kata mcp --connect` attached and exited cleanly at EOF: {stderr}"
            );
            let frames: BTreeMap<String, Value> = String::from_utf8(output.stdout)
                .expect("stdout is UTF-8")
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    let frame: Value = serde_json::from_str(line).unwrap_or_else(|e| {
                        panic!("non-protocol stdout: {e}\n{line}\nstderr: {stderr}")
                    });
                    (frame["id"].to_string(), frame)
                })
                .collect();
            frames
        })
        .await
        .expect("the driver thread");
        server.abort();
        frames
    });

    let seen = seen.lock().expect("the recorder lock").clone();
    let is_marker = |(path, body): &(String, Value), n: usize| {
        path == "/api/v1/ops/observe" && body["execution_id"] == marker_execution_id(n).as_str()
    };
    let mut positions = Vec::new();
    for n in 0..=corpus.len() {
        let at = seen
            .iter()
            .position(|request| is_marker(request, n))
            .unwrap_or_else(|| {
                panic!(
                    "R10 is BLIND: marker {n} (an `observe` the attached server proxies) never \
                     reached the API, so no call's requests can be told apart. Recorded: {seen:?}"
                )
            });
        positions.push(at);
    }
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "R10's markers reached the API out of order: {positions:?}"
    );
    corpus
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let frame = frames
                .get(&json!(format!("form-{index}")).to_string())
                .unwrap_or_else(|| panic!("no answer to form {index}"))
                .clone();
            AttachedOutcome {
                ok: frame["result"]["structuredContent"]["ok"] == true,
                reached_the_api: positions[index + 1] - positions[index] > 1,
                frame,
            }
        })
        .collect()
}

/// R10, and R9 for the tool and form rows. The DEFAULT `kata mcp`, attached to a
/// real API router, is driven through a corpus GENERATED from its own tools'
/// `inputSchema`s ([`generated_form_corpus`]); a call it answers with a SUCCESS while
/// putting no request on the API was served at the caller, outside its principal,
/// and must be excused by a row of [`MCP_SERVED_OUTSIDE_THE_API`] (R10). Each tool or
/// form row must in turn be served at the caller by at least one call (R9): a row
/// whose form now reaches the API is stale.
///
/// What reached the API is read off the requests the API received — a layer in front
/// of its router — never off the MCP server's own routing (`remote_invoke`,
/// `check_reads_the_workstation`), which is what this checks.
///
/// The refused set is bounded by the corpus: a form served at the caller only for a
/// value [`sample_values`] does not generate (a string other than a name or an
/// existing `.star` path, a number other than `1`, a non-empty array or object, a
/// combination of two non-required properties) is not refused. A call the caller
/// REFUSES without reaching the API serves nothing and is not refused either.
#[test]
fn the_attached_mcp_serves_at_the_caller_only_its_pinned_forms() {
    let schemas = mcp_tool_input_schemas();
    let project = tempfile::tempdir().expect("a project directory");
    let pack = project.path().join("derivation-probe.star");
    std::fs::write(
        &pack,
        "verdict = stage(id = \"verdict\", agent = \"default\", prompt = \"review the diff\")\n\
         workflow(\"derivation-probe\", root = [verdict])\n",
    )
    .expect("write the probe pack");
    let mut corpus = generated_form_corpus(&schemas, &pack.display().to_string());
    // `author` scaffolds into the project, and a form of it given the probe pack's
    // path with `force` overwrites that pack; its forms are driven last, so every
    // other form reads the project as written here.
    corpus.sort_by_key(|(tool, _)| tool == "author");
    let outcomes = drive_attached_forms(project.path(), &corpus);

    let mut unexcused = Vec::new();
    let mut served_at_the_caller = 0;
    for ((tool, arguments), outcome) in corpus.iter().zip(&outcomes) {
        if !outcome.ok || outcome.reached_the_api {
            continue;
        }
        served_at_the_caller += 1;
        if !MCP_SERVED_OUTSIDE_THE_API
            .iter()
            .any(|row| row.excuses(tool, arguments))
        {
            unexcused.push(format!("{tool} {arguments}"));
        }
    }
    assert!(
        unexcused.is_empty(),
        "DERIVATION (R10): the attached `kata mcp` served these calls at the caller — a \
         success with no request on the API — and no row of MCP_SERVED_OUTSIDE_THE_API \
         names them:\n  {}\nMCP derives from the API; what it serves outside it is the \
         closed list ADR 0004 pins.",
        unexcused.join("\n  ")
    );

    let stale: Vec<String> = MCP_SERVED_OUTSIDE_THE_API
        .iter()
        .filter(|row| row.mcp_form.is_some())
        .filter(|row| {
            !corpus
                .iter()
                .zip(&outcomes)
                .any(|((tool, arguments), outcome)| {
                    outcome.ok && !outcome.reached_the_api && row.excuses(tool, arguments)
                })
        })
        .map(|row| format!("{} {} ({})", row.kind, row.name, row.why))
        .collect();
    assert!(
        stale.is_empty(),
        "DERIVATION (R9): rows of MCP_SERVED_OUTSIDE_THE_API the attached `kata mcp` no \
         longer serves at the caller:\n  {}\nOnce MCP proxies a form or drops it, its row \
         must go.",
        stale.join("\n  ")
    );

    let proxied_ok = outcomes
        .iter()
        .filter(|outcome| outcome.ok && outcome.reached_the_api)
        .count();
    assert!(
        served_at_the_caller > 0 && proxied_ok > 0,
        "R10 is VACUOUS: of {} calls, {served_at_the_caller} were served at the caller and \
         {proxied_ok} answered ok through the API; the rig must see both. Frames: {:?}",
        corpus.len(),
        outcomes
            .iter()
            .map(|outcome| &outcome.frame)
            .collect::<Vec<_>>()
    );
}

/// R5-R6. The installed skill is sugar twice over: the `kata <cmd>` lines it
/// teaches derive from the CLI, and the tool names it teaches derive from what
/// the MCP server actually advertises.
///
/// The split between the two is syntactic and deliberate. A span that starts
/// `kata ` is a CLI invocation and is answerable to the clap tree; a bare
/// backticked operation name is a TOOL and is answerable to `tools/list`. So
/// SKILL.md may still tell an operator to run `kata run approve` — a command,
/// checked against the CLI — while it may not present `approve` as a tool the
/// agent can call, because the MCP surface advertises no such tool. That
/// second case is exactly the drift a hand-kept list accumulates.
#[test]
fn the_installed_skill_names_nothing_its_principals_do_not_have() {
    let skill_text = installed_skill_text();
    let visible: BTreeSet<String> = cli_commands()
        .into_iter()
        .filter(|c| !c.hidden)
        .map(|c| c.path)
        .collect();
    let (mcp_tools, _) = mcp_surface();
    let advertised: BTreeSet<String> = mcp_tools.iter().map(|t| t.name.clone()).collect();

    // R5 — every `kata <cmd>` the skill teaches must exist on the CLI.
    let invocations = kata_command_invocations(&skill_text);
    assert!(
        !invocations.is_empty(),
        "DERIVATION (R5) is VACUOUS: the installed SKILL.md names no `kata <cmd>` invocation at \
         all, so the scanner is blind rather than satisfied. Either the skill stopped naming \
         commands or `kata_command_invocations` stopped seeing them."
    );
    let unbacked: Vec<String> = invocations
        .iter()
        .filter(|inv| longest_cli_prefix(inv, &visible).is_none())
        .cloned()
        .collect();
    assert!(
        unbacked.is_empty(),
        "DERIVATION (R5): the installed skill teaches `kata` invocations the CLI does not have: \
         {unbacked:?}.\nThe skill is sugar over the CLI; it cannot advertise a command its \
         principal does not carry. {} visible command paths were searched, longest prefix first.",
        visible.len()
    );

    // R6 — every bare operation name the skill teaches as a tool must be one
    // the MCP server advertises.
    let taught: BTreeSet<String> = backticked_spans(&skill_text)
        .into_iter()
        .filter(|span| {
            kata_op_contract::Operation::ALL
                .iter()
                .any(|op| op.as_str() == span)
        })
        .collect();
    assert!(
        !taught.is_empty(),
        "DERIVATION (R6) is VACUOUS: the installed SKILL.md teaches no operation by name at all."
    );
    // The refused set is the OPERATION NAMES the skill teaches, intersected against
    // what MCP advertises. A backticked span that names no operation at all — an
    // invented `deploy_to_prod` — is NOT refused here, and deliberately: any
    // heuristic wide enough to catch it false-positives on ordinary backticked
    // prose, and a guard that cries wolf on documentation is worse than this bound.
    // R5 covers the `kata <cmd>` spelling; this covers the bare-operation spelling.
    let unadvertised: Vec<String> = taught.difference(&advertised).cloned().collect();
    assert!(
        unadvertised.is_empty(),
        "DERIVATION (R6): the installed skill names operations the MCP server does not advertise: \
         {unadvertised:?}.\n`tools/list` is the complete list of what an agent can drive — the \
         skill's own scope-ceiling section says so. Naming an unadvertised operation sends the \
         agent to a call that returns `unknown tool` or the OPERATE-only refusal. Advertised: \
         {advertised:?}"
    );
}

/// The other half of the invariant, and the half a parity check gets wrong: a
/// principal is ALLOWED to carry what its sugar does not expose.
///
/// Written as an assertion rather than a comment because it is the
/// counterfactual for the two tests above. If either is ever "fixed" into
/// symmetry, these numbers stop being true and this test names the direction
/// the fix went.
#[test]
fn sugar_may_be_a_strict_subset_of_its_principal() {
    let (mcp_tools, _) = mcp_surface();
    let advertised: BTreeSet<&str> = mcp_tools.iter().map(|t| t.name.as_str()).collect();
    let served_by_the_api = api_served_operations();
    let api_serves: BTreeSet<&str> = served_by_the_api.iter().map(String::as_str).collect();

    let api_only: Vec<&str> = api_serves.difference(&advertised).copied().collect();
    assert_eq!(
        api_only,
        vec![
            "approve",
            "cancel",
            "discharge_stop",
            "forge_reconcile",
            "promote",
            "reject"
        ],
        "the API serves six operations MCP does not advertise, and that is the DESIGN: each \
         requires `ApiScope::Approve` and the agent surface holds `Operate`. This is a subset, \
         not debt — no disposition row is owed for any of them, and a guard that demanded parity \
         here would be demanding that a workload be able to approve its own gates."
    );
    let mcp_only: Vec<&str> = advertised.difference(&api_serves).copied().collect();
    assert_eq!(
        mcp_only,
        vec!["author"],
        "the one tool MCP advertises that the API does not serve is `author`, a row of \
         MCP_SERVED_OUTSIDE_THE_API under ADR 0004 — the derivation runs the other way, and \
         this is the counterfactual that says so"
    );

    let skill_text = installed_skill_text();
    let named = kata_command_invocations(&skill_text);
    let visible = cli_commands().into_iter().filter(|c| !c.hidden).count();
    assert!(
        named.len() < visible,
        "the installed skill names {} `kata` commands out of {visible} visible ones. A skill \
         obliged to name every command would be a copy of `--help`, not sugar.",
        named.len()
    );
}

// ---------------------------------------------------------------------------
// CONVERGENCE: one spelling across the faces
// ---------------------------------------------------------------------------
//
// The MCP surface and the Rust SDK converge on ONE spelling, and
// `Operation::ALL` wins, because it is the only VERSIONED one of the three
// vocabularies and therefore the only one on which changing a spelling has a
// compatibility story at all.
//
// The two guards below state that verdict once each, in the direction the
// surface law (AGENTS.md, "Four principal surfaces, and two derived ones")
// assigns:
//
//   * MCP is DERIVED from the API, so its tool names are the API's operation
//     names — `the_mcp_tool_names_are_exactly_the_api_operations_it_exposes`.
//   * the SDK is a PRINCIPAL, so its method names are `Operation::ALL`'s —
//     `the_sdk_names_every_operation_it_fronts_with_the_contracts_own_word`.
//
// Neither asserts PAYLOAD convergence and neither should be read as if it did.
// The SDK's `observe` still returns an `ExecutionRecord` where the contract's
// `ObserveResponse` has its own named fields, and its `list` still returns full
// records where `ListResponse` is four fields per row. Convergence is a
// SPELLING verdict; the payload divergence stays recorded on the `observe` /
// `list` `http_routes_whose_path_names_it` rows in `ABSENCE_DISPOSITIONS` above.

/// The operations the Rust SDK FRONTS, and why.
///
/// Hand-written, because "does this face serve this operation?" is the one
/// judgement no scan can make — the same reason `ABSENCE_DISPOSITIONS` above is
/// hand-written — and pinned by [`SDK_FRONTED_OPERATION_COUNT`] in the same
/// idiom, so an operation cannot join or leave the SDK without moving a number
/// in the diff.
///
/// What is NOT hand-written is the SPELLING: the guard reads each name out of
/// `Operation::as_str()` and looks for it in the SDK's declaration scan. A row
/// here says only WHICH operations the SDK fronts; the contract says what they
/// are CALLED.
///
/// `(operation, why the SDK fronts it)`.
const SDK_FRONTED_OPERATIONS: &[(&str, &str)] = &[
    (
        "run",
        "`POST /api/v1/executions`, returning an `Execution` handle. Six argument shapes \
         (`run`, `run_with_external_inputs`, `run_with_params`, and the three `run_starlark*` \
         twins) funnel into one private `submit_inner`; only the bare one carries the \
         operation's own word, which is what makes the mapping one-for-one. NOTE the neighbour \
         this creates: `KataClient::run_agent` is `POST /api/v1/agents/run`, ONE agent call, and \
         is not this operation or a shape of it — the same `run` collision the HTTP and CLI faces \
         already carry, recorded on \
         `the_cross_face_cells_that_match_by_spelling_only_are_named`, now reproduced on the SDK \
         as the price of the contract's word.",
    ),
    ("observe", "`GET /api/v1/executions/{id}`."),
    (
        "list",
        "`GET /api/v1/executions`. The \
         `limit`/`status` shape is `list_filtered`, which is an argument shape and not a \
         second name for the operation.",
    ),
    ("approve", "`POST /api/v1/executions/{id}/approve`."),
    ("reject", "`POST /api/v1/executions/{id}/reject`."),
    ("cancel", "`POST /api/v1/executions/{id}/cancel`."),
    ("promote", "`POST /api/v1/executions/{id}/promote`."),
    (
        "forge_reconcile",
        "`POST /api/v1/ops/forge_reconcile`, the envelope decoded into typed exports.",
    ),
];

/// Pinned length of [`SDK_FRONTED_OPERATIONS`].
const SDK_FRONTED_OPERATION_COUNT: usize = 8;

/// Convergence, SDK half: for every operation the Rust SDK
/// fronts there is EXACTLY ONE public method spelled with that operation's own
/// contract word, and for every operation it does NOT front there is none.
///
/// Both directions are the point. The first is convergence; the second is the
/// derived-surface rule applied to a principal — a face may carry less than the
/// contract, but it may not spell an operation's word at a method that is not
/// that operation. Three operations are deliberately absent (`author`, `check`,
/// `discharge_stop`); the first two are workstation-local and the last is
/// reachable only through the untyped `invoke_op`, which stays recorded as debt
/// on its `sdk_method_named_for_it` row in `ABSENCE_DISPOSITIONS` and is NOT
/// discharged here. `discharge_stop` lands on both agent-facing faces or on
/// neither, which is why this guard does not quietly add it to one.
#[test]
fn the_sdk_names_every_operation_it_fronts_with_the_contracts_own_word() {
    assert_eq!(
        SDK_FRONTED_OPERATIONS.len(),
        SDK_FRONTED_OPERATION_COUNT,
        "SDK_FRONTED_OPERATIONS has {} rows and SDK_FRONTED_OPERATION_COUNT says {}. The table \
         records which operations the SDK serves; its size is pinned so one cannot join or leave \
         without saying so.",
        SDK_FRONTED_OPERATIONS.len(),
        SDK_FRONTED_OPERATION_COUNT
    );

    let contract: BTreeSet<&str> = kata_op_contract::Operation::ALL
        .iter()
        .map(|op| op.as_str())
        .collect();
    let fronted: BTreeSet<&str> = SDK_FRONTED_OPERATIONS
        .iter()
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        fronted.len(),
        SDK_FRONTED_OPERATIONS.len(),
        "SDK_FRONTED_OPERATIONS names an operation twice"
    );
    let invented: Vec<&str> = fronted.difference(&contract).copied().collect();
    assert!(
        invented.is_empty(),
        "SDK_FRONTED_OPERATIONS names {invented:?}, which is not a class-A operation. The table \
         may only select from `Operation::ALL`; it may not invent an operation for the SDK to \
         front."
    );
    assert!(
        !fronted.is_empty() && fronted.len() < contract.len(),
        "the fronted set must be a non-empty STRICT subset of the contract, or this guard is \
         asserting parity rather than derivation"
    );

    // The independent artifact: the SDK's own source, scanned for public
    // declarations. Nothing here consults the client crate's beliefs about
    // itself — `sdk_methods` reads the `pub fn` lines off disk.
    let sdk = sdk_methods(&workspace_root());
    let mut occurrences: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for op in kata_op_contract::Operation::ALL {
        let name = op.as_str();
        let hits: Vec<String> = sdk
            .iter()
            .filter(|m| m.name == name)
            .map(|m| format!("{}::{}", m.module, m.name))
            .collect();
        occurrences.insert(name, hits);
    }

    // Convergence: every fronted operation is spelled with the contract's word,
    // exactly once.
    let mut unconverged = Vec::new();
    for (name, why) in SDK_FRONTED_OPERATIONS {
        match occurrences[name].len() {
            1 => {}
            0 => unconverged.push(format!(
                "{name}: the SDK fronts this operation ({why}) and declares no `pub fn {name}`"
            )),
            n => unconverged.push(format!(
                "{name}: {n} public declarations are spelled `{name}` ({:?}); one operation, one \
                 method",
                occurrences[name]
            )),
        }
    }
    assert!(
        unconverged.is_empty(),
        "CONVERGENCE: the Rust SDK does not spell every operation it \
         fronts with the contract's own word:\n  {}\n`Operation::ALL` \
         (`crates/op-contract/src/operation.rs`) is the surviving vocabulary because it is the \
         only VERSIONED one of the three; the SDK is the surface that moves.",
        unconverged.join("\n  ")
    );

    // No false advertisement: an operation the SDK does not front may not have
    // its word taken by an SDK method.
    let squatted: Vec<String> = contract
        .difference(&fronted)
        .filter(|name| !occurrences[*name].is_empty())
        .map(|name| format!("{name}: {:?}", occurrences[name]))
        .collect();
    assert!(
        squatted.is_empty(),
        "CONVERGENCE: the SDK spells an operation's word at a method that \
         does not front that operation:\n  {}\nEither the method fronts the operation, in which \
         case it belongs in SDK_FRONTED_OPERATIONS, or it does not, in which case it must not \
         take the contract's word.",
        squatted.join("\n  ")
    );
}

/// Convergence, MCP half: the tool names a real `kata mcp`
/// advertises are EXACTLY the operation names its principal — the API — places
/// within the surface's `Operate` scope.
///
/// What this adds over `mcp_advertises_no_tool_the_api_does_not_serve`, which
/// is R1-R4 and R7-R9 and stays the derived-surface guard: R1 proves the advertised set is a
/// SUBSET of the operations (no orphan tool), and this proves the two sets are
/// EQUAL for the operations the surface exposes (no silently DROPPED tool, and
/// no tool whose name is an operation's but not the operation the scope table
/// says belongs here). The right-hand side is computed from
/// `kata_api::op_dispatch::operation_required_scope` — the PRINCIPAL's own
/// function. `cli::mcp::surface_permits`, which `tools_list` filters with,
/// reads the same function, so both sides move together under a
/// misclassification in `operation_required_scope` (an `Operate` operation
/// moved to another scope) and this stays green: the literal-list test named
/// below refuses that.
///
/// It is deliberately NOT keyed on a literal name list. The literal list lives
/// in `cli::mcp::tools`'s own
/// `tools_list_advertises_only_the_operate_callable_tools`, which exists to
/// survive a change to the PREDICATE; this one exists to survive a change to
/// the SPELLING, and reads the shipped binary rather than `tools_list()`.
#[test]
fn the_mcp_tool_names_are_exactly_the_api_operations_it_exposes() {
    use kata_types::identity::ApiScope;

    let (mcp_tools, _) = mcp_surface();
    let advertised: BTreeSet<String> = mcp_tools.iter().map(|t| t.name.clone()).collect();
    assert_eq!(
        advertised.len(),
        mcp_tools.len(),
        "`tools/list` advertised the same tool name twice"
    );

    let principal_operate: BTreeSet<String> = kata_op_contract::Operation::ALL
        .iter()
        .filter(|op| kata_api::op_dispatch::operation_required_scope(**op) == ApiScope::Operate)
        .map(|op| op.as_str().to_string())
        .collect();

    assert_eq!(
        advertised, principal_operate,
        "CONVERGENCE: the MCP surface's tool names are not the API's \
         operation names for the operations it exposes.\nadvertised by the running server: \
         {advertised:?}\noperations `operation_required_scope` puts at `ApiScope::Operate`: \
         {principal_operate:?}\nMCP is DERIVED from the API, so the tool \
         name IS the operation's `Operation::as_str()` — not a second spelling that happens to \
         agree."
    );

    assert!(
        !advertised.is_empty() && advertised.len() < kata_op_contract::Operation::ALL.len(),
        "the advertised set must be a non-empty STRICT subset of the operations, or this \
         guard is satisfied by a surface that advertises everything or nothing. Advertised \
         {advertised:?} of {}",
        kata_op_contract::Operation::ALL.len()
    );
}
