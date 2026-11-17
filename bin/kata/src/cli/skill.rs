//! `kata skill install` — wire kata into a host coding agent.
//!
//! One command registers kata as an MCP server for a host agent AND installs a
//! kata skill that teaches that agent the author → check → run → observe loop
//! through the kata MCP tools (`author` / `check` / `run` / `observe` / `list`).
//!
//! For `--host claude-code` (fully automated) it writes two project-local files,
//! both idempotently — re-running updates in place and never clobbers unrelated
//! content:
//!
//! * `<dir>/.mcp.json` — an ADDITIVE merge of an `mcpServers.kata` entry that
//!   launches `kata mcp` as a client of the installed main. Any other servers already registered in the file are
//!   preserved; only the `kata` entry is (re)written.
//! * `<dir>/.claude/skills/kata/SKILL.md` — the kata authoring-loop skill.
//!
//! For `--host codex` there is no project-local MCP registration or skill file
//! format (Codex reads a GLOBAL `~/.codex/config.toml`), so `install` prints the
//! manual registration steps rather than mutating a user-global file — a
//! documented narrowing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::types::SkillHost;

/// MCP server key kata registers itself under in the host's `.mcp.json`.
const KATA_SERVER_NAME: &str = "kata";

/// Dispatch `kata skill install`.
pub(crate) fn run_skill_install_cmd(host: SkillHost, dir: PathBuf) -> Result<()> {
    match host {
        SkillHost::ClaudeCode => install_claude_code(&dir),
        SkillHost::Codex => {
            print_codex_narrowing(&dir);
            Ok(())
        }
    }
}

/// Install the kata MCP registration + skill into a Claude Code project rooted
/// at `dir`. Idempotent: the MCP entry is merged additively and the skill file
/// is written in place.
fn install_claude_code(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("kata skill install: creating project dir {}", dir.display()))?;

    let mcp_path = dir.join(".mcp.json");
    let entry = kata_server_entry(dir)?;
    let merged = merge_mcp_registration(read_existing_mcp(&mcp_path)?, entry)?;
    write_json_pretty(&mcp_path, &merged)?;

    let skill_path = dir
        .join(".claude")
        .join("skills")
        .join("kata")
        .join("SKILL.md");
    if let Some(parent) = skill_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "kata skill install: creating skill dir {}",
                parent.display()
            )
        })?;
    }
    std::fs::write(&skill_path, SKILL_MD).with_context(|| {
        format!(
            "kata skill install: writing skill file {}",
            skill_path.display()
        )
    })?;

    println!("kata skill install (claude-code):");
    println!("  MCP server  → {}", mcp_path.display());
    println!("  kata skill  → {}", skill_path.display());
    println!(
        "\nRestart Claude Code (or reload MCP servers) so it launches `kata mcp` \
         and picks up the kata skill."
    );
    Ok(())
}

/// The `mcpServers.kata` value written into a Claude Code `.mcp.json`. Launches
/// `kata mcp` from the ABSOLUTE path of the running binary so the registration
/// survives a `$PATH` that does not contain kata. MCP attaches to the one
/// installed main by default; installing a project skill never creates another
/// engine or selects project-local durable state.
fn kata_server_entry(_dir: &Path) -> Result<Value> {
    let exe = std::env::current_exe()
        .context("kata skill install: resolving the running kata binary path")?;
    Ok(json!({
        "command": exe.to_string_lossy(),
        "args": ["mcp"],
    }))
}

/// Read the existing `.mcp.json` as a JSON value, or `None` when absent. A
/// present-but-unparseable file is a hard error rather than a silent clobber —
/// the whole point of the additive merge is to never destroy operator content.
fn read_existing_mcp(path: &Path) -> Result<Option<Value>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            if text.trim().is_empty() {
                return Ok(None);
            }
            let value = serde_json::from_str(&text).with_context(|| {
                format!(
                    "kata skill install: {} exists but is not valid JSON; refusing to \
                     clobber it — fix or remove it and re-run",
                    path.display()
                )
            })?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("kata skill install: reading {}", path.display())),
    }
}

/// Additively merge the `kata` server entry into an existing `.mcp.json` value
/// (or a fresh document when `existing` is `None`). EVERY other `mcpServers`
/// entry and every unrelated top-level key is preserved; only `mcpServers.kata`
/// is (re)written, which is what makes re-running idempotent.
fn merge_mcp_registration(existing: Option<Value>, kata_entry: Value) -> Result<Value> {
    let mut root = match existing {
        None => json!({}),
        Some(value) => value,
    };
    let object = root.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "kata skill install: existing .mcp.json is not a JSON object; refusing to clobber it"
        )
    })?;

    let servers = object
        .entry("mcpServers".to_string())
        .or_insert_with(|| json!({}));
    let servers = servers.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "kata skill install: existing .mcp.json `mcpServers` is not a JSON object; \
             refusing to clobber it"
        )
    })?;
    servers.insert(KATA_SERVER_NAME.to_string(), kata_entry);
    Ok(root)
}

/// Write `value` as pretty JSON with a trailing newline.
fn write_json_pretty(path: &Path, value: &Value) -> Result<()> {
    let mut text =
        serde_json::to_string_pretty(value).context("kata skill install: serializing .mcp.json")?;
    text.push('\n');
    std::fs::write(path, text)
        .with_context(|| format!("kata skill install: writing {}", path.display()))
}

/// Print the manual steps for wiring kata into Codex — the documented narrowing.
/// Codex reads a GLOBAL `~/.codex/config.toml` (there is no project-local MCP
/// file or skill format to write additively), so `install` does not mutate it.
fn print_codex_narrowing(dir: &Path) {
    let exe = std::env::current_exe()
        .map_or_else(|_| "kata".to_string(), |p| p.to_string_lossy().into_owned());
    println!(
        "kata skill install --host codex is a documented NARROWING.\n\
         \n\
         Codex registers MCP servers in a GLOBAL user file (~/.codex/config.toml)\n\
         and has no project-local skill-file format, so kata does not mutate it\n\
         automatically. Register kata manually by adding this table to\n\
         ~/.codex/config.toml:\n\
         \n\
         [mcp_servers.kata]\n\
         command = \"{exe}\"\n\
         args = [\"mcp\"]\n\
         \n\
         Then paste the kata authoring-loop guidance into your Codex prompt/\n\
         AGENTS.md. To get the fully-automated path (an `.mcp.json` + SKILL.md in\n\
         {dir}), run `kata skill install --host claude-code` instead.",
        dir = dir.display()
    );
}

/// The kata authoring-loop skill installed for Claude Code. Teaches the host
/// agent to drive kata's lifecycle through the REAL MCP tools exposed by
/// `kata mcp` (`author` / `check` / `run` / `observe` / `list`), and names the
/// OPERATE-only ceiling so the agent does not try to resolve its own gates.
///
/// The scope-ceiling section does not ENUMERATE the refused operations: a
/// hand-kept list drifts (it would have to learn every new operation, such as
/// `discharge_stop`), and those tools are not in `tools/list`, so
/// the agent cannot see them and needs no warning about them. What the prose
/// must track is the ADVERTISED set, and
/// `skill_md_teaches_exactly_the_tools_the_mcp_surface_advertises` holds that
/// against the one predicate rather than against a second list.
///
/// The numbered loop is deliberately NOT generated from
/// `cli::mcp::tools::operation_description`. This prose carries the polling
/// contract, the inline-`workflow_starlark` form, and the `data.terminal`
/// branch, none of which a one-line tool description holds; generating it would
/// lose all three to remove a duplication that does not exist.
const SKILL_MD: &str = r#"---
name: kata
description: >-
  Author, check, run, and observe kata workflows through the kata MCP server.
  Use when the user wants to build or run a durable multi-agent workflow with
  kata — orchestrating coding agents with caching, sandboxing, and replay.
---

# kata authoring loop

kata is a durable agent-orchestration engine. It is registered here as an MCP
server (the `kata` server launches `kata mcp`), so you drive its whole lifecycle
through MCP tools — no shell required for the core loop.

Workflows are written in **Starlark** (`.star`). TOML is only the node config
(`kata.toml`); there is no TOML or Markdown workflow format.

## The loop: author → check → run → observe

Use these kata MCP tools, in order:

1. **`author`** — scaffold a project-local kata config and workflow library
   (equivalent to `kata init`). Run once per project.
2. **`check`** — compile and verify a workflow into the checked execution IR
   WITHOUT running it. Pass `{ "workflow": "<name-or-path>" }`, or
   `{ "all": true }` to check every effective workflow. A library name is checked
   by the main, against the library a `run` by that name compiles from; a `.star`
   path and `all` are checked here, on your machine, and name the node facts they
   could not judge in `deferred_node_facts`. Fix every diagnostic it reports
   before running — `check` is your fast, model-free feedback loop.
3. **`run`** — submit a workflow for execution on the installed kata main. Pass a
   library `{ "workflow": "<name>" }`, a `.star` path (read here and submitted
   as its source), or an inline `{ "workflow_starlark": "<source>" }` body to
   author-and-submit in one call.
   It returns an `execution_id`.
4. **`observe`** — read an execution's state. Pass `{ "execution_id": "<id>" }`
   and poll until `data.terminal == true`; the terminal `data.status` is
   `completed` / `failed` / `cancelled`.
5. **`list`** — enumerate recent executions (id, status, workflow, started) when
   you need to find a run you did not just submit.

## Discovering the DSL

- The MCP resource `kata://workflows/dsl-catalog` (via `resources/read`) is the
  machine-readable catalog of every workflow builtin — its kwargs, types, and
  defaults. Read it instead of guessing the DSL.
- Curated starting points live under `workflows/examples/` in the kata
  distribution; copy-adapt one rather than writing from scratch.

## Scope ceiling (important)

The kata MCP surface is **OPERATE-only** and advertises only the tools it can
actually run, so `tools/list` is the complete list of what you can drive. The
human-gate mutations are not exposed here at all; a workflow that parks on a
human gate is resolved by the operator from the kata CLI/API with an
approve-scoped token.

## Tips

- Always `check` before `run`; attachment failures never create a scratch main.
- `observe` returns a typed envelope; branch on `data.status`, not prose.
- On a tool error, the JSON-RPC error `data` carries a typed `OpError`
  (`code` / `retryable` / `exit_code`) — retry only when `retryable == true`.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_into_empty_creates_mcp_servers_kata() {
        let merged =
            merge_mcp_registration(None, json!({ "command": "kata", "args": ["mcp"] })).unwrap();
        assert_eq!(merged["mcpServers"]["kata"]["command"], "kata");
        assert_eq!(merged["mcpServers"]["kata"]["args"][0], "mcp");
    }

    #[test]
    fn merge_preserves_existing_servers_and_top_level_keys() {
        let existing = json!({
            "mcpServers": {
                "other": { "command": "other-server", "args": ["serve"] }
            },
            "unrelatedTopLevel": { "keep": true }
        });
        let merged = merge_mcp_registration(
            Some(existing),
            json!({ "command": "kata", "args": ["mcp"] }),
        )
        .unwrap();
        // The pre-existing server is untouched.
        assert_eq!(merged["mcpServers"]["other"]["command"], "other-server");
        // The unrelated top-level key survives.
        assert_eq!(merged["unrelatedTopLevel"]["keep"], true);
        // And kata was added.
        assert_eq!(merged["mcpServers"]["kata"]["command"], "kata");
    }

    #[test]
    fn merge_is_idempotent_and_overwrites_only_kata() {
        let first =
            merge_mcp_registration(None, json!({ "command": "old", "args": ["mcp"] })).unwrap();
        let second = merge_mcp_registration(
            Some(first),
            json!({ "command": "new", "args": ["mcp", "--config", "x"] }),
        )
        .unwrap();
        // Re-running replaced the kata entry in place; still exactly one kata.
        assert_eq!(second["mcpServers"]["kata"]["command"], "new");
        assert_eq!(second["mcpServers"]["kata"]["args"][2], "x");
        assert_eq!(
            second["mcpServers"].as_object().unwrap().len(),
            1,
            "no duplicate kata entries"
        );
    }

    #[test]
    fn merge_refuses_non_object_root() {
        let err = merge_mcp_registration(Some(json!([1, 2, 3])), json!({})).unwrap_err();
        assert!(err.to_string().contains("not a JSON object"));
    }

    #[test]
    fn merge_refuses_non_object_mcp_servers() {
        let err =
            merge_mcp_registration(Some(json!({ "mcpServers": "nope" })), json!({})).unwrap_err();
        assert!(
            err.to_string()
                .contains("`mcpServers` is not a JSON object")
        );
    }

    /// The prose must teach every advertised tool and name no
    /// unadvertised one.
    ///
    /// The two halves are NOT the same kind of claim, and the derived-surface
    /// rule makes the difference load-bearing. "Name no
    /// unadvertised one" is the INVARIANT — the skill is sugar and may not
    /// advertise what its principal does not have; it is enforced across the
    /// faces by `the_installed_skill_names_nothing_its_principals_do_not_have`
    /// in `bin/kata/tests/surface_inventory.rs`, which refuses it on a
    /// REAL install driven against a REAL `tools/list`. "Teach every advertised
    /// tool" is a STANDARD this one document holds itself to: the derivation
    /// check deliberately permits a sugar surface to expose less than its
    /// principal, so nothing cross-face refuses an untaught tool. It is kept
    /// here because an advertised tool the skill silently forgot is a real
    /// defect and this is the only reader that sees it — and it is safe to keep
    /// as an equality precisely because it is NOT symmetric in blame: when it
    /// fires, the guilty party is always SKILL.md.
    ///
    /// Deriving the expectation from the predicate is CORRECT here, and it is
    /// the opposite of the choice made in
    /// `tools_list_advertises_only_the_operate_callable_tools`, which pins the
    /// predicate against literal names. That test holds the predicate; this one
    /// only holds the prose to it. It also does not read `tools_list`, so it is
    /// not redundant with the list guards: it is the one that catches SKILL.md
    /// drift — the `discharge_stop` omission this replaces — and
    /// it stays green when the list filter is reverted, by design.
    #[test]
    fn skill_md_teaches_exactly_the_tools_the_mcp_surface_advertises() {
        for op in kata_op_contract::Operation::ALL {
            let taught = SKILL_MD.contains(&format!("`{}`", op.as_str()));
            assert_eq!(
                taught,
                crate::cli::mcp::surface_permits(*op),
                "SKILL.md must teach every advertised tool and name no unadvertised one: {op}"
            );
        }
    }

    #[test]
    fn skill_md_names_the_real_tools_and_is_starlark_only() {
        for tool in ["author", "check", "run", "observe", "list"] {
            assert!(
                SKILL_MD.contains(&format!("`{tool}`")),
                "SKILL.md teaches the `{tool}` MCP tool"
            );
        }
        // Starlark-only reality: no TOML/Markdown workflow format claim.
        assert!(SKILL_MD.contains("Starlark"));
        assert!(
            !SKILL_MD.contains("TOML or Markdown workflow")
                || SKILL_MD.contains("no TOML or Markdown workflow format"),
            "SKILL.md must not advertise a TOML/Markdown workflow format"
        );
    }
}
