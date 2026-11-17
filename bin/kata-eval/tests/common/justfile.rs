//! The justfile model this crate's STRUCTURAL gate checks share: Just's own parse of
//! the recipe graph (`just --dump-format json`), the small shell surface a reachable
//! recipe may use, and the two reachability answers — every POSSIBLE edge (for
//! exclusions) and the STRUCTURALLY required ones (for positive coverage).
//!
//! Moved here verbatim from `gate_exclusion.rs` when `protected_property_ledger.rs`
//! became its second reader: a second copy of a recipe-graph parser would be two
//! readers free to disagree about which recipes a gate runs, which is the mirror
//! defect in the one place it would make both checks lie at once.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

use serde::Deserialize;
use serde_json::Value;

use super::repo_root;

#[derive(Debug, Deserialize)]
pub struct Justfile {
    #[serde(skip)]
    pub source: String,
    #[serde(default)]
    pub aliases: BTreeMap<String, Alias>,
    /// Every `NAME := value` assignment, as Just's own expression tree.
    #[serde(default)]
    pub assignments: BTreeMap<String, Value>,
    pub recipes: BTreeMap<String, Recipe>,
    /// The `set` settings Just's JSON reports.
    #[serde(default)]
    pub settings: Value,
}

#[derive(Debug, Deserialize)]
pub struct Alias {
    pub target: String,
}

#[derive(Debug, Deserialize)]
pub struct Recipe {
    #[serde(default)]
    pub attributes: Vec<Value>,
    #[serde(default)]
    pub body: Vec<Vec<Value>>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
}

#[derive(Debug, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub kind: String,
    /// The default's expression tree, `null` when the parameter has none.
    #[serde(default)]
    pub default: Value,
}

#[derive(Debug, Deserialize)]
pub struct Dependency {
    pub recipe: String,
    /// The arguments the header passes, as expression trees.
    #[serde(default)]
    pub arguments: Value,
}

pub const DYNAMIC: char = '\u{e000}';

pub fn parse_justfile(path: &Path) -> Justfile {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading justfile {}: {e}", path.display()));
    let output = Command::new("just")
        .args(["--justfile", path.to_str().expect("UTF-8 justfile path")])
        .args(["--dump-format", "json", "--dump"])
        .output()
        .unwrap_or_else(|e| panic!("running `just --dump-format json --dump`: {e}"));
    assert!(
        output.status.success(),
        "Just must parse {} before its gate graph can be verified:\n{}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut justfile: Justfile = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("decoding Just JSON for {}: {e}", path.display()));
    justfile.source = source;
    justfile
}

pub fn justfile_text() -> Justfile {
    let path = repo_root().join("justfile");
    parse_justfile(&path)
}

/// Render one recipe body from Just's own parsed JSON metadata.
///
/// A HEADER MAY CARRY PARAMETERS **AND DEPENDENCIES**. `smoke filter="": build` is a
/// recipe header and the dependency executes without a body-level `just` call. The
/// former hand parser accepted that header but discarded the dependency. Recipe
/// discovery and header edges now come from the same parser that executes the file.
/// Dynamic Just expressions are retained as [`DYNAMIC`] rather than guessed.
pub fn recipe_body(justfile: &Justfile, name: &str) -> Option<String> {
    let recipe = justfile.recipes.get(name)?;
    let mut body = String::new();
    for line in &recipe.body {
        for fragment in line {
            match fragment {
                Value::String(literal) => body.push_str(literal),
                _ => body.push(DYNAMIC),
            }
        }
        body.push('\n');
    }
    Some(body)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Separator {
    Sequence,
    And,
    Or,
    Pipe,
}

#[derive(Debug)]
pub enum ShellToken {
    Word { text: String, dynamic: bool },
    Separator(Separator),
}

/// Tokenize only the shell surface this verifier claims to understand: words,
/// quotes/escapes, comments, and the command separators `;`, `&&`, `||`, and `|`.
/// Just interpolations are represented by [`DYNAMIC`] before tokenization.
pub fn shell_tokens(line: &str) -> Result<Vec<ShellToken>, String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut dynamic = false;
    let mut quote = None;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;

    let finish_word = |tokens: &mut Vec<ShellToken>, word: &mut String, dynamic: &mut bool| {
        if !word.is_empty() || *dynamic {
            tokens.push(ShellToken::Word {
                text: std::mem::take(word),
                dynamic: std::mem::take(dynamic),
            });
        }
    };

    while index < chars.len() {
        let ch = chars[index];
        if escaped {
            word.push(ch);
            escaped = false;
            index += 1;
            continue;
        }
        if ch == DYNAMIC {
            dynamic = true;
            index += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            match ch {
                '\\' if delimiter == '"' => escaped = true,
                _ if ch == delimiter => quote = None,
                _ => word.push(ch),
            }
            index += 1;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            '#' if word.is_empty() => break,
            ' ' | '\t' => finish_word(&mut tokens, &mut word, &mut dynamic),
            ';' => {
                finish_word(&mut tokens, &mut word, &mut dynamic);
                tokens.push(ShellToken::Separator(Separator::Sequence));
            }
            '&' if chars.get(index + 1) == Some(&'&') => {
                finish_word(&mut tokens, &mut word, &mut dynamic);
                tokens.push(ShellToken::Separator(Separator::And));
                index += 1;
            }
            '|' => {
                finish_word(&mut tokens, &mut word, &mut dynamic);
                if chars.get(index + 1) == Some(&'|') {
                    tokens.push(ShellToken::Separator(Separator::Or));
                    index += 1;
                } else {
                    tokens.push(ShellToken::Separator(Separator::Pipe));
                }
            }
            _ => word.push(ch),
        }
        index += 1;
    }
    if escaped || quote.is_some() {
        return Err("unterminated shell quote or escape".to_string());
    }
    finish_word(&mut tokens, &mut word, &mut dynamic);
    Ok(tokens)
}

#[derive(Clone, Debug)]
pub struct Call {
    pub recipe: String,
    pub args: Vec<String>,
    pub structural_candidate: bool,
}

pub fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name.chars().enumerate().all(|(i, ch)| {
            ch == '_' || ch.is_ascii_alphanumeric() && (i > 0 || !ch.is_ascii_digit())
        })
}

/// Find literal Just calls at shell command position.
///
/// Accepted calls are direct `just [--no-dotenv] RECIPE ...` commands, optionally
/// preceded by literal environment assignments or `exec`, with multiple commands
/// separated by `;`/`&&`/`||`/`|`. Quoted prose and ordinary arguments do not count.
/// A dynamic executable or dynamic recipe name is refused. `eval` and `sh -c`/`bash
/// -c` are refused because they can construct an invisible call. Shell control-flow
/// constructs and every compound command line are possible-only: positive coverage
/// requires a top-level standalone call or a header dependency. External script
/// contents are outside this justfile-only proof.
pub fn calls_on_line(line: &str, recipe: &str) -> Vec<Call> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return Vec::new();
    }
    let dynamic_command = trimmed.starts_with('$')
        || trimmed.starts_with("eval ")
        || trimmed.starts_with("sh -c ")
        || trimmed.starts_with("bash -c ")
        || ["if $", "then $", "elif $", "while $", "until $", "do $"]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix));
    // Complex shell that contains no literal Just token cannot contribute a
    // statically named edge. Avoid pretending this small lexer parses jq programs,
    // heredocs, or multiline shell data. Explicit dynamic command positions and
    // evaluators are still refused below.
    if !line.contains("just") && !dynamic_command {
        return Vec::new();
    }
    assert!(
        !(trimmed.starts_with("just()")
            || trimmed.starts_with("function just")
            || trimmed.starts_with("alias just=")),
        "a reachable recipe may not shadow the `just` executable: {recipe}: {line}"
    );
    assert!(
        !((line.contains("$(") || line.contains('`')) && line.contains("just")),
        "nested shell evaluation containing `just` in reachable recipe `{recipe}` is outside the gate verifier's supported language: {line}"
    );
    let tokens = shell_tokens(line).unwrap_or_else(|e| {
        panic!("unsupported shell in reachable recipe `{recipe}`: {e}: {line}")
    });
    let mut calls = Vec::new();
    let mut segment = Vec::new();
    let mut before = None;
    let compound = tokens
        .iter()
        .any(|token| matches!(token, ShellToken::Separator(_)));

    let inspect = |segment: &[&ShellToken], before: Option<Separator>, calls: &mut Vec<Call>| {
        let words: Vec<(&str, bool)> = segment
            .iter()
            .filter_map(|token| match token {
                ShellToken::Word { text, dynamic } => Some((text.as_str(), *dynamic)),
                ShellToken::Separator(_) => None,
            })
            .collect();
        if words.is_empty() {
            return;
        }
        let mut at = 0;
        while at < words.len() && is_assignment(words[at].0) {
            at += 1;
        }
        let mut control_flow = false;
        while words.get(at).is_some_and(|(word, dynamic)| {
            !dynamic
                && matches!(
                    *word,
                    "if" | "then" | "elif" | "else" | "while" | "until" | "do" | "!"
                )
        }) {
            control_flow = true;
            at += 1;
        }
        while at < words.len() && is_assignment(words[at].0) {
            at += 1;
        }
        if words
            .get(at)
            .is_some_and(|(word, dynamic)| !dynamic && *word == "env")
        {
            at += 1;
            loop {
                let Some((word, dynamic)) = words.get(at).copied() else {
                    return;
                };
                if dynamic {
                    break;
                }
                match word {
                    "-u" | "--unset" => at += 2,
                    "-i" | "--ignore-environment" | "--" => at += 1,
                    _ if word.starts_with("--unset=") || is_assignment(word) => at += 1,
                    _ if word.starts_with('-') => panic!(
                        "unsupported `env` option in reachable recipe `{recipe}`: {word}: {line}"
                    ),
                    _ => break,
                }
            }
        }
        if words
            .get(at)
            .is_some_and(|(word, dynamic)| !dynamic && *word == "command")
        {
            at += 1;
            if words
                .get(at)
                .is_some_and(|(word, dynamic)| !dynamic && matches!(*word, "-v" | "-V"))
            {
                return; // Shell command lookup, not execution.
            }
            if words
                .get(at)
                .is_some_and(|(word, dynamic)| !dynamic && *word == "--")
            {
                at += 1;
            }
        }
        if words
            .get(at)
            .is_some_and(|(word, dynamic)| !dynamic && *word == "exec")
        {
            at += 1;
        }
        let Some((command, command_dynamic)) = words.get(at).copied() else {
            return;
        };
        assert!(
            !(command_dynamic || command.contains('$')),
            "dynamic shell command in reachable recipe `{recipe}` is outside the gate verifier's supported language: {line}"
        );
        if command == "eval"
            || ((command == "sh" || command == "bash")
                && words.iter().skip(at + 1).any(|(word, _)| *word == "-c"))
        {
            panic!(
                "dynamic shell evaluation in reachable recipe `{recipe}` is outside the gate verifier's supported language: {line}"
            );
        }
        if command != "just" {
            return;
        }
        at += 1;
        while let Some((flag, dynamic)) = words.get(at).copied() {
            if dynamic {
                break;
            }
            if flag == "--no-dotenv" || flag == "--quiet" || flag == "-q" {
                at += 1;
            } else if flag.starts_with('-') {
                panic!("unsupported `just` option in reachable recipe `{recipe}`: {flag}: {line}");
            } else {
                break;
            }
        }
        let Some((called, dynamic)) = words.get(at).copied() else {
            panic!("a reachable `just` call must name a recipe: {line}");
        };
        assert!(
            !(dynamic || called.contains('$') || called.is_empty()),
            "dynamic `just` recipe name in reachable recipe `{recipe}` is outside the gate verifier's supported language: {line}"
        );
        calls.push(Call {
            recipe: called.to_string(),
            args: words
                .iter()
                .skip(at + 1)
                .map(|(word, dynamic)| {
                    if *dynamic {
                        DYNAMIC.to_string()
                    } else {
                        (*word).to_string()
                    }
                })
                .collect(),
            structural_candidate: !compound
                && !control_flow
                && !matches!(before, Some(Separator::Or | Separator::Pipe)),
        });
    };

    for token in &tokens {
        if let ShellToken::Separator(separator) = token {
            inspect(&segment, before, &mut calls);
            segment.clear();
            before = Some(*separator);
        } else {
            segment.push(token);
        }
    }
    inspect(&segment, before, &mut calls);
    calls
}

/// One LOGICAL line of a recipe body: `\`-continuations folded, a non-shebang
/// recipe's line prefix (`-`, `@`, indentation) trimmed, and whether the line sits
/// inside a shell control structure (conditional, loop, case, function body).
pub struct LogicalLine {
    pub text: String,
    pub inside_control: bool,
}

/// Apply the small amount of cross-line shell structure needed for truthful
/// positive structural coverage. A line inside a conditional, loop, case, or
/// function definition runs only POSSIBLY: it can serve an exclusion, never a
/// required-source edge. Shared by [`calls_in_body`] (Just calls) and by any reader
/// that needs the same answer for another command on the line.
pub fn logical_lines(body: &str, recipe: &str) -> Vec<LogicalLine> {
    let shebang = body
        .lines()
        .next()
        .is_some_and(|line| line.trim_start().starts_with("#!"));
    let mut conditional_depth = 0usize;
    let mut physical_lines = Vec::new();
    let mut continued = String::new();
    for physical in body.lines() {
        let trimmed_end = physical.trim_end();
        if let Some(prefix) = trimmed_end.strip_suffix('\\') {
            continued.push_str(prefix);
            continued.push(' ');
        } else if continued.is_empty() {
            physical_lines.push(physical.to_string());
        } else {
            continued.push_str(physical);
            physical_lines.push(std::mem::take(&mut continued));
        }
    }
    assert!(
        continued.is_empty(),
        "unterminated shell line continuation in reachable recipe `{recipe}`"
    );

    let mut lines = Vec::with_capacity(physical_lines.len());
    for line in &physical_lines {
        let trimmed = line.trim();
        if trimmed == "fi" || trimmed == "done" || trimmed == "esac" || trimmed.starts_with('}') {
            conditional_depth = conditional_depth.saturating_sub(1);
        }
        let opens_control = trimmed.starts_with("if ")
            || trimmed.starts_with("for ")
            || trimmed.starts_with("while ")
            || trimmed.starts_with("until ")
            || trimmed.starts_with("case ")
            || trimmed == "{"
            || trimmed.ends_with(") {")
            || trimmed.ends_with("(){");
        let closes_inline = (trimmed.starts_with("if ") && trimmed.ends_with(" fi"))
            || ((trimmed.starts_with("for ")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("until "))
                && trimmed.ends_with(" done"))
            || (trimmed.starts_with("case ") && trimmed.ends_with(" esac"));
        if opens_control {
            conditional_depth += 1;
        }
        let text = if shebang {
            line.clone()
        } else {
            line.trim_start_matches([' ', '\t', '-', '@']).to_string()
        };
        lines.push(LogicalLine {
            text,
            inside_control: conditional_depth > 0,
        });
        if closes_inline {
            conditional_depth = conditional_depth.saturating_sub(1);
        }
    }
    assert_eq!(
        conditional_depth, 0,
        "unbalanced or unsupported shell control structure in reachable recipe `{recipe}`"
    );
    lines
}

/// Every literal Just call in `body`. Calls inside conditionals, loops, cases, or
/// function definitions remain possible edges for exclusion, but never
/// required-source edges.
pub fn calls_in_body(body: &str, recipe: &str) -> Vec<Call> {
    logical_lines(body, recipe)
        .into_iter()
        .flat_map(|line| {
            calls_on_line(&line.text, recipe)
                .into_iter()
                .map(move |mut call| {
                    call.structural_candidate &= !line.inside_control;
                    call
                })
        })
        .collect()
}

pub fn resolved_recipe<'a>(justfile: &'a Justfile, name: &'a str) -> &'a str {
    justfile
        .aliases
        .get(name)
        .map_or(name, |alias| alias.target.as_str())
}

/// Expand the unambiguous multi-target suffix of `just A ... B ...`.
/// Fixed singular parameters belong to A; once they are consumed, every
/// remaining literal must begin another known recipe. Variadic signatures are
/// intentionally opaque because Just may assign all remaining words to them.
pub fn possible_targets(justfile: &Justfile, call: Call, caller: &str) -> Vec<String> {
    let primary = resolved_recipe(justfile, &call.recipe).to_owned();
    let recipe = justfile
        .recipes
        .get(&primary)
        .unwrap_or_else(|| panic!("reachable just recipe `{primary}` must exist"));
    if recipe
        .parameters
        .iter()
        .any(|parameter| parameter.kind != "singular")
    {
        return vec![primary];
    }
    if call.args.len() <= recipe.parameters.len() {
        return vec![primary];
    }
    let mut targets = vec![primary];
    for token in call.args.into_iter().skip(recipe.parameters.len()) {
        assert!(
            !token.contains(DYNAMIC),
            "dynamic multi-recipe Just invocation in reachable recipe `{caller}` is unsupported"
        );
        let target = resolved_recipe(justfile, &token).to_owned();
        assert!(
            justfile.recipes.contains_key(&target),
            "extra argument `{token}` after a fixed-arity recipe in reachable `{caller}` is not a known Just target"
        );
        targets.push(target);
    }
    targets
}

/// Possible reachability is used for exclusions: every statically recognized call
/// is followed. Header dependencies come from Just's parser, not a local grammar.
pub fn reachable_recipes(justfile: &Justfile, root: &str) -> BTreeMap<String, String> {
    let mut pending = vec![root.to_owned()];
    let mut seen = BTreeSet::new();
    let mut reachable = BTreeMap::new();

    while let Some(name) = pending.pop() {
        let name = resolved_recipe(justfile, &name).to_owned();
        if !seen.insert(name.clone()) {
            continue;
        }

        let recipe = justfile
            .recipes
            .get(&name)
            .unwrap_or_else(|| panic!("reachable just recipe `{name}` must exist"));
        pending.extend(
            recipe
                .dependencies
                .iter()
                .map(|dependency| dependency.recipe.clone()),
        );
        let body = recipe_body(justfile, &name).expect("recipe was just resolved");
        for call in calls_in_body(&body, &name) {
            pending.extend(possible_targets(justfile, call, &name));
        }
        reachable.insert(name, body);
    }

    reachable
}

/// Recipes structurally named by top-level standalone calls, plus header dependencies.
///
/// This is NOT runtime-execution evidence: an earlier `exit 0`, shell option changes,
/// traps, and other arbitrary-shell behavior can bypass even a standalone source line.
/// No conditional, loop, function body, command chain, pipeline, or fallback satisfies
/// even this narrower structural set. Actual lane discharge still requires a runtime
/// receipt; this set only prevents an echo/branch from satisfying the static guard.
pub fn structurally_required_recipes(justfile: &Justfile, root: &str) -> BTreeMap<String, String> {
    let mut pending = vec![root.to_owned()];
    let mut seen = BTreeSet::new();
    let mut reachable = BTreeMap::new();
    while let Some(name) = pending.pop() {
        let name = resolved_recipe(justfile, &name).to_owned();
        if !seen.insert(name.clone()) {
            continue;
        }
        let recipe = justfile
            .recipes
            .get(&name)
            .unwrap_or_else(|| panic!("reachable just recipe `{name}` must exist"));
        pending.extend(
            recipe
                .dependencies
                .iter()
                .map(|dependency| dependency.recipe.clone()),
        );
        let body = recipe_body(justfile, &name).expect("recipe was just resolved");
        pending.extend(
            calls_in_body(&body, &name)
                .into_iter()
                .filter(|call| call.structural_candidate)
                .map(|call| call.recipe),
        );
        reachable.insert(name, body);
    }
    reachable
}

pub fn parse_justfile_source(source: &str) -> Justfile {
    let dir = tempfile::tempdir().expect("temporary Just workspace");
    let path = dir.path().join("justfile");
    std::fs::write(&path, source).expect("write temporary justfile");
    parse_justfile(&path)
}
