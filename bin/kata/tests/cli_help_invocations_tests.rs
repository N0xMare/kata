//! Every `kata …` invocation the CLI's own help PRINTS must resolve against the
//! CLI's own command tree.
//!
//! A help string naming a subcommand the tree does not have (an `ops park`
//! where the operation is `run park`) exits 2 with clap's
//! unrecognized-subcommand error when an operator types it: nothing can be
//! inferred — no `infer_subcommands`, no `allow_external_subcommands`, no
//! aliases — and nothing else in the tree fails on the discrepancy.
//!
//! The string is a doc comment, and pinning one corrected string would only pin
//! the string. So this pins the CLASS instead: harvest every backticked `kata …`
//! span out of every `about` / `long_about` / arg `help` / arg `long_help` in
//! the tree clap renders, and walk each one down that same tree. A namespace
//! nobody can type cannot survive here regardless of which help text grows it.
//!
//! The harvest deliberately reads the CONSTRUCTED `clap::Command`, not the
//! source text: doc comments reach operators only by way of clap, so this
//! observes exactly what `--help` will print.

use std::collections::BTreeSet;

use clap::CommandFactory;
use kata::cli::Cli;

/// A `kata …` invocation printed by some help string, and where it was printed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrintedInvocation {
    /// Space-joined command path whose help carried it, e.g. `kata run cancel`.
    site: String,
    /// The backticked span verbatim, e.g. `kata ops park`.
    text: String,
}

/// Could this token be a SUBCOMMAND name, as opposed to a flag or a placeholder?
///
/// Subcommand names in this CLI are lowercase kebab (`import-inbox`,
/// `discharge-stop`). Anything holding a `-` prefix, angle brackets, a dot, a
/// slash, or an uppercase letter is a flag, a placeholder, or a value — the walk
/// stops there rather than guessing, because a value is not something this test
/// can adjudicate.
fn looks_like_subcommand_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !token.starts_with('-')
}

/// Pull the backtick-delimited spans out of one help string.
fn backticked_spans(text: &str) -> Vec<&str> {
    text.split('`')
        .enumerate()
        .filter_map(|(index, span)| (index % 2 == 1).then_some(span))
        .collect()
}

/// Walk `command`'s help surfaces and those of every subcommand, recording each
/// backticked span that begins with the binary name.
fn collect_printed_invocations(
    command: &clap::Command,
    path: &[String],
    out: &mut BTreeSet<PrintedInvocation>,
) {
    let mut site_parts = path.to_vec();
    site_parts.insert(0, "kata".to_string());
    let site = site_parts.join(" ");

    let mut help_sources: Vec<String> = Vec::new();
    if let Some(about) = command.get_about() {
        help_sources.push(about.to_string());
    }
    if let Some(long_about) = command.get_long_about() {
        help_sources.push(long_about.to_string());
    }
    for arg in command.get_arguments() {
        if let Some(help) = arg.get_help() {
            help_sources.push(help.to_string());
        }
        if let Some(long_help) = arg.get_long_help() {
            help_sources.push(long_help.to_string());
        }
    }

    for source in &help_sources {
        for span in backticked_spans(source) {
            let normalized = span.split_whitespace().collect::<Vec<_>>().join(" ");
            if normalized == "kata" || normalized.starts_with("kata ") {
                out.insert(PrintedInvocation {
                    site: site.clone(),
                    text: normalized,
                });
            }
        }
    }

    for sub in command.get_subcommands() {
        let mut child = path.to_vec();
        child.push(sub.get_name().to_string());
        collect_printed_invocations(sub, &child, out);
    }
}

/// Resolve a printed invocation against the command tree.
///
/// Returns `Err(the token that does not resolve)`. Tokens are consumed only
/// while they keep naming a real subcommand of the node reached so far; the walk
/// halts at the first token that is not subcommand-shaped (a flag, a
/// placeholder, a value), which is the only honest stopping point — this test
/// adjudicates namespaces, not arguments.
fn resolve(root: &clap::Command, invocation: &str) -> Result<(), String> {
    let mut tokens = invocation.split_whitespace();
    assert_eq!(tokens.next(), Some("kata"), "harvest guarantees this");
    let mut node = root;
    for token in tokens {
        if !looks_like_subcommand_token(token) {
            return Ok(());
        }
        if let Some(next) = node.find_subcommand(token) {
            node = next;
        } else if node.get_subcommands().next().is_none() {
            // The node takes no subcommands at all, so this token is a
            // positional value (`kata check std.hello`). Nothing to check.
            return Ok(());
        } else {
            return Err(token.to_string());
        }
    }
    Ok(())
}

/// The class guard. RED before the `kata ops park` → `kata run park` fix with
/// exactly one row; GREEN after.
#[test]
fn every_kata_invocation_printed_in_help_names_a_real_subcommand() {
    let mut root = Cli::command();
    root.build();
    let mut printed = BTreeSet::new();
    collect_printed_invocations(&root, &[], &mut printed);

    assert!(
        printed.len() > 20,
        "the harvest found only {} backticked `kata …` spans, which means it stopped seeing \
         clap's help surfaces rather than that the help stopped naming commands",
        printed.len()
    );

    let mut unresolved: Vec<String> = Vec::new();
    for invocation in &printed {
        if let Err(token) = resolve(&root, &invocation.text) {
            unresolved.push(format!(
                "`{}` (printed by `{}` --help): `{token}` is not a subcommand there",
                invocation.text, invocation.site
            ));
        }
    }

    assert!(
        unresolved.is_empty(),
        "help text names {} invocation(s) an operator cannot type:\n  {}",
        unresolved.len(),
        unresolved.join("\n  ")
    );
}

/// The specific line the class guard was built from, kept as a named receipt so
/// a reader grepping `kata ops` lands on the reason rather than on nothing.
#[test]
fn the_cancel_help_names_kata_run_park_not_a_nonexistent_ops_namespace() {
    let mut root = Cli::command();
    root.build();
    let run = root.find_subcommand("run").expect("`kata run` exists");
    let cancel = run
        .find_subcommand("cancel")
        .expect("`kata run cancel` exists");
    let help = cancel
        .get_long_about()
        .or_else(|| cancel.get_about())
        .expect("RunCmd::Cancel carries a doc comment")
        .to_string();

    assert!(
        help.contains("kata run park"),
        "`kata run cancel --help` must name the reclaim operation an operator can type; got:\n{help}"
    );
    assert!(
        !help.contains("kata ops"),
        "no `ops` subcommand exists and none can be inferred; got:\n{help}"
    );
    assert!(
        root.find_subcommand("ops").is_none(),
        "if an `ops` namespace is ever added, revisit this test rather than deleting it"
    );
}
