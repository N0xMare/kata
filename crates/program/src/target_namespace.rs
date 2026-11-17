//! The `{{ target.* }}` template namespace: the execution's FROZEN target, as
//! admission resolved it and the invocation binds it.
//!
//! * `target.spec` — the spelling the run asked for (`trunk`, `pr:42`).
//! * `target.kind` — `trunk` or `pr`.
//! * `target.head` — the frozen `/work` fork base, 40 hex digits; `none` for an
//!   unborn trunk.
//! * `target.branch` — the landable branch (trunk's name); `none` for a pull
//!   request and an unborn trunk.
//! * `target.compare` — `{name, commit, merge_base}`, the review baseline
//!   (`name` is `none` for a trunk target, whose baseline is the head's first
//!   parent); `none` when the head has no baseline.
//! * `target.pr` — `{number, url, title, title_truncated, body,
//!   body_truncated, base_ref, head_ref}` for a pull-request target; `none`
//!   otherwise. `title` and `body` are frozen cut to 512 B / 8 KiB at a
//!   character boundary, and each `_truncated` flag says whether its cut
//!   dropped anything.
//! * `target.changed_files` — `[{path, kind}]` from `compare.merge_base` to
//!   `head`, `kind` one of `added` / `modified` / `deleted`, at most
//!   [`MAX_TARGET_CHANGED_FILES`] entries; `target.changed_files_truncated` says
//!   whether entries were cut.
//! * `target.diff` — the git-format text diff over the same range, at most
//!   [`MAX_TARGET_DIFF_BYTES`] and cut at a whole line;
//!   `target.diff_truncated` says whether it was cut.
//!
//! `changed_files` and `diff` are `none` (and both flags `false`) when
//! `target.compare` is `none`. Every key is always present, so a strict render
//! never trips on a kind difference.
//!
//! Every value is a function of the frozen target: the facts are the
//! invocation's, and `changed_files` / `diff` are computed through the provider
//! from the two frozen commit ids — the pins keep both alive — when a render
//! first reads them. A re-render by the same build is therefore identical. One
//! input is not frozen: `diff`'s hunk boundaries are jj-lib's line diff's, so a
//! main upgraded to a jj-lib whose line diff differs between a stage's first
//! dispatch and its re-render (a retry, a resume) can render the same change
//! split into different hunks. A provider read that fails makes the key an
//! invalid value, which fails the render that reads it, naming the read.
//!
//! # Trust
//!
//! The PR author controls `pr.title`, `pr.body`, `pr.head_ref`, and the paths
//! and contents in `changed_files` and `diff`; the forge or repository controls
//! `pr.base_ref`, `pr.url` and `compare.name`; a branch name — `branch`, and so
//! `spec` — may legally hold `$`, `;`, `&` or a backtick. A shell stage's
//! `run=` may therefore read only [`TARGET_SHELL_SAFE_READS`] bare; `kata check`
//! refuses any other read there unless `shquote` makes it a quoted word where
//! the shell reads that word as one word (`template_untrusted_in_run`,
//! [`untrusted_reads_in_command`]). A prompt may
//! read every key.

use std::collections::BTreeSet;

use minijinja::Error;
use minijinja::machinery::ast::{CallArg, Expr, Stmt};

use crate::shell_position::ShellPosition;

/// The most `target.changed_files` entries a render carries.
pub const MAX_TARGET_CHANGED_FILES: usize = 2_000;

/// The most bytes of `target.diff` a render carries.
pub const MAX_TARGET_DIFF_BYTES: usize = 256 * 1024;

/// Every key the namespace answers, in enumeration order.
pub const TARGET_KEYS: &[&str] = &[
    "spec",
    "kind",
    "head",
    "branch",
    "compare",
    "pr",
    "changed_files",
    "changed_files_truncated",
    "diff",
    "diff_truncated",
];

/// The keys `target.compare` answers.
pub(crate) const TARGET_COMPARE_KEYS: &[&str] = &["name", "commit", "merge_base"];

/// The keys `target.pr` answers.
pub(crate) const TARGET_PR_KEYS: &[&str] = &[
    "number",
    "url",
    "title",
    "title_truncated",
    "body",
    "body_truncated",
    "base_ref",
    "head_ref",
];

/// The reads whose rendered text no third party chooses and no shell
/// interprets: the 40-hex commit ids, the kind label, the PR number and the four
/// booleans. Each renders only `[0-9a-z_]` characters (or `none`). Every other
/// read — a key outside this list, a key below one of these (`target.head.x`),
/// the bare namespace, a subscript — is untrusted in a shell `run=`.
pub(crate) const TARGET_SHELL_SAFE_READS: &[&str] = &[
    "head",
    "kind",
    "compare.commit",
    "compare.merge_base",
    "pr.number",
    "pr.title_truncated",
    "pr.body_truncated",
    "changed_files_truncated",
    "diff_truncated",
];

/// The untrusted `target` reads in a shell `run=` template, each spelled as
/// written (`target.pr.title`, `target` for the bare namespace or a
/// subscript): the refused set of `template_untrusted_in_run`.
///
/// A read is a `target` variable followed by attribute names. It is SAFE when
/// its dotted path below `target` is one of [`TARGET_SHELL_SAFE_READS`]. Any
/// other read is untrusted, and allowed in exactly two places:
///
/// 1. inside an output `{{ … }}` whose OUTERMOST operation is the `shquote`
///    filter, emitted where the shell reads that `'…'` as ONE word
///    ([`crate::shell_position`]): in the command text or inside `$( … )`, at
///    every position the template's control flow can reach that output from.
///    Emitted anywhere else — inside `"…"`, `'…'`, a backtick, `${ … }`, a
///    comment, a heredoc body, right after `\` or `$`, in a macro, `{% set %}`
///    or filter block body, or where the lexer cannot follow the text — it is
///    [`UntrustedReads::misquoted`];
/// 2. anywhere inside an `{% if %}` / `{% elif %}` condition, or the condition of
///    an inline `a if cond else b` — a condition decides which text renders and
///    is never rendered itself.
///
/// Every other untrusted read is [`UntrustedReads::bare`], wherever it sits: an
/// output that does not END in `| shquote` (`{{ target.pr.title }}`, `{{
/// target.pr.title | shquote | upper }}`), a `{% set %}`, a `{% for %}`
/// iterable, a macro or call argument, a filter block. The walk covers every
/// branch and loop body, taken or not, and does not track scope: a template
/// that assigns its own `target` is read as the namespace.
///
/// NOT checked: what the command does with a word. `sh -c {{ target.pr.title |
/// shquote }}` hands the title to a second shell as one word, which then runs
/// it; so does `eval`, `ssh`, `xargs sh` and anything else that parses an
/// argument as shell.
///
/// # Errors
///
/// The parser's own error for a template that does not parse.
pub(crate) fn untrusted_reads_in_command(source: &str) -> Result<UntrustedReads, Error> {
    let ast = minijinja::machinery::parse(
        source,
        "<run>",
        minijinja::syntax::SyntaxConfig,
        minijinja::machinery::WhitespaceConfig::default(),
    )?;
    let mut walk = UntrustedWalk::default();
    walk.stmt(&ast, Positions::start());
    Ok(walk.reads)
}

/// [`untrusted_reads_in_command`]'s answer.
#[derive(Debug, Default)]
pub(crate) struct UntrustedReads {
    /// Reads outside any trailing `| shquote`.
    pub(crate) bare: BTreeSet<String>,
    /// Reads inside a trailing `| shquote` emitted where its `'…'` is not one
    /// shell word.
    pub(crate) misquoted: BTreeSet<String>,
}

impl UntrustedReads {
    pub(crate) fn is_empty(&self) -> bool {
        self.bare.is_empty() && self.misquoted.is_empty()
    }
}

/// The shell positions a template statement can start at: one per control
/// path, collapsed to [`ShellPosition::unknown`] once any path is lost or the
/// set grows past [`MAX_POSITIONS`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Positions(BTreeSet<ShellPosition>);

/// The most distinct positions a walk carries before it stops following them.
const MAX_POSITIONS: usize = 64;

/// The most times a loop body is walked looking for its positions' fixed point.
const MAX_LOOP_WALKS: usize = 8;

impl Positions {
    fn start() -> Self {
        Self(BTreeSet::from([ShellPosition::start()]))
    }

    fn unknown() -> Self {
        Self(BTreeSet::from([ShellPosition::unknown()]))
    }

    fn normalized(self) -> Self {
        if self.0.len() > MAX_POSITIONS || self.0.iter().any(ShellPosition::is_unknown) {
            return Self::unknown();
        }
        self
    }

    fn union(mut self, other: Self) -> Self {
        self.0.extend(other.0);
        self.normalized()
    }

    fn map(self, step: impl Fn(&mut ShellPosition)) -> Self {
        Self(
            self.0
                .into_iter()
                .map(|mut position| {
                    step(&mut position);
                    position
                })
                .collect(),
        )
        .normalized()
    }

    fn take_one_word(&self) -> bool {
        self.0.iter().all(ShellPosition::takes_one_word)
    }
}

#[derive(Default)]
struct UntrustedWalk {
    reads: UntrustedReads,
    /// An expression walked since the last reset calls a bare name — a macro,
    /// `caller()`, `super()` — whose output is template text, not a value.
    calls_by_name: bool,
}

/// The attribute path below `target` that `expr` reads, when it is a `target`
/// read: `Some([])` for the bare namespace, `Some(["pr", "title"])` for
/// `target.pr.title`. A subscript anywhere in the chain reads an unknown key,
/// spelled as `None` inside.
fn target_path<'a>(expr: &Expr<'a>) -> Option<Vec<Option<&'a str>>> {
    match expr {
        Expr::Var(var) if var.id == "target" => Some(Vec::new()),
        Expr::GetAttr(attr) => target_path(&attr.expr).map(|mut path| {
            path.push(Some(attr.name));
            path
        }),
        Expr::GetItem(item) => target_path(&item.expr).map(|mut path| {
            path.push(None);
            path
        }),
        _ => None,
    }
}

impl UntrustedWalk {
    fn stmts(&mut self, stmts: &[Stmt<'_>], at: Positions) -> Positions {
        stmts.iter().fold(at, |at, stmt| self.stmt(stmt, at))
    }

    /// Walk `stmt` starting at `at`; the positions it can end at.
    fn stmt(&mut self, stmt: &Stmt<'_>, at: Positions) -> Positions {
        match stmt {
            Stmt::Template(template) => self.stmts(&template.children, at),
            Stmt::EmitRaw(raw) => at.map(|position| position.raw(raw.raw)),
            Stmt::EmitExpr(emit) => {
                if matches!(&emit.expr, Expr::Filter(filter) if filter.name == "shquote") {
                    let mut operand = Self::default();
                    operand.expr(&emit.expr);
                    if !at.take_one_word() {
                        let UntrustedReads { bare, misquoted } = operand.reads;
                        self.reads
                            .misquoted
                            .extend(bare.into_iter().chain(misquoted));
                    }
                    return at.map(ShellPosition::quoted_word);
                }
                self.calls_by_name = false;
                self.expr(&emit.expr);
                if std::mem::take(&mut self.calls_by_name) {
                    return Positions::unknown();
                }
                at.map(ShellPosition::word)
            }
            Stmt::ForLoop(for_loop) => {
                self.expr(&for_loop.target);
                self.expr(&for_loop.iter);
                if let Some(filter) = &for_loop.filter_expr {
                    self.expr(filter);
                }
                // Every position an iteration can start at: the entry, and
                // the end of any number of iterations.
                let mut entry = at.clone();
                let mut walks = 0;
                loop {
                    let next = at.clone().union(self.stmts(&for_loop.body, entry.clone()));
                    if next == entry {
                        break;
                    }
                    entry = next;
                    walks += 1;
                    if walks == MAX_LOOP_WALKS {
                        entry = Positions::unknown();
                        self.stmts(&for_loop.body, entry.clone());
                        break;
                    }
                }
                entry.union(self.stmts(&for_loop.else_body, at))
            }
            // The condition is never rendered; only the bodies are.
            Stmt::IfCond(cond) => {
                let taken = self.stmts(&cond.true_body, at.clone());
                taken.union(self.stmts(&cond.false_body, at))
            }
            Stmt::WithBlock(with) => {
                for (name, value) in &with.assignments {
                    self.expr(name);
                    self.expr(value);
                }
                self.stmts(&with.body, at)
            }
            Stmt::Set(set) => {
                self.expr(&set.target);
                self.expr(&set.expr);
                at
            }
            // A captured body lands wherever the variable is printed.
            Stmt::SetBlock(set) => {
                self.expr(&set.target);
                if let Some(filter) = &set.filter {
                    self.expr(filter);
                }
                self.stmts(&set.body, Positions::unknown());
                at
            }
            Stmt::AutoEscape(escape) => {
                self.expr(&escape.enabled);
                self.stmts(&escape.body, at)
            }
            // The filter rewrites its body's text.
            Stmt::FilterBlock(block) => {
                self.expr(&block.filter);
                self.stmts(&block.body, Positions::unknown());
                Positions::unknown()
            }
            Stmt::Block(block) => self.stmts(&block.body, at),
            Stmt::Import(import) => {
                self.expr(&import.expr);
                self.expr(&import.name);
                at
            }
            Stmt::FromImport(import) => {
                self.expr(&import.expr);
                for (name, alias) in &import.names {
                    self.expr(name);
                    if let Some(alias) = alias {
                        self.expr(alias);
                    }
                }
                at
            }
            Stmt::Extends(extends) => {
                self.expr(&extends.name);
                Positions::unknown()
            }
            Stmt::Include(include) => {
                self.expr(&include.name);
                Positions::unknown()
            }
            // A macro's body lands wherever it is called.
            Stmt::Macro(def) => {
                for expr in def.args.iter().chain(&def.defaults) {
                    self.expr(expr);
                }
                self.stmts(&def.body, Positions::unknown());
                at
            }
            Stmt::CallBlock(block) => {
                self.expr(&block.call.expr);
                self.args(&block.call.args);
                for expr in block
                    .macro_decl
                    .args
                    .iter()
                    .chain(&block.macro_decl.defaults)
                {
                    self.expr(expr);
                }
                self.stmts(&block.macro_decl.body, Positions::unknown());
                Positions::unknown()
            }
            Stmt::Do(call) => {
                self.expr(&call.call.expr);
                self.args(&call.call.args);
                at
            }
        }
    }

    fn args(&mut self, args: &[CallArg<'_>]) {
        for arg in args {
            match arg {
                CallArg::Pos(expr)
                | CallArg::Kwarg(_, expr)
                | CallArg::PosSplat(expr)
                | CallArg::KwargSplat(expr) => self.expr(expr),
            }
        }
    }

    fn expr(&mut self, expr: &Expr<'_>) {
        if let Some(path) = target_path(expr) {
            self.target_read(&path);
            // A subscript's index is an expression of its own.
            self.subscripts(expr);
            return;
        }
        match expr {
            Expr::Var(_) | Expr::Const(_) => {}
            Expr::Slice(slice) => {
                self.expr(&slice.expr);
                for part in [&slice.start, &slice.stop, &slice.step]
                    .into_iter()
                    .flatten()
                {
                    self.expr(part);
                }
            }
            Expr::UnaryOp(op) => self.expr(&op.expr),
            Expr::BinOp(op) => {
                self.expr(&op.left);
                self.expr(&op.right);
            }
            // The condition is never rendered; only the branches are.
            Expr::IfExpr(cond) => {
                self.expr(&cond.true_expr);
                if let Some(otherwise) = &cond.false_expr {
                    self.expr(otherwise);
                }
            }
            Expr::Filter(filter) => {
                if let Some(operand) = &filter.expr {
                    self.expr(operand);
                }
                self.args(&filter.args);
            }
            Expr::Test(test) => {
                self.expr(&test.expr);
                self.args(&test.args);
            }
            Expr::GetAttr(attr) => self.expr(&attr.expr),
            Expr::GetItem(item) => {
                self.expr(&item.expr);
                self.expr(&item.subscript_expr);
            }
            Expr::Call(call) => {
                if matches!(&call.expr, Expr::Var(_)) {
                    self.calls_by_name = true;
                }
                self.expr(&call.expr);
                self.args(&call.args);
            }
            Expr::List(list) => {
                for item in &list.items {
                    self.expr(item);
                }
            }
            Expr::Map(map) => {
                for item in map.keys.iter().chain(&map.values) {
                    self.expr(item);
                }
            }
        }
    }

    /// Walk the index expressions of every subscript in a `target` read chain.
    fn subscripts(&mut self, expr: &Expr<'_>) {
        match expr {
            Expr::GetAttr(attr) => self.subscripts(&attr.expr),
            Expr::GetItem(item) => {
                self.subscripts(&item.expr);
                self.expr(&item.subscript_expr);
            }
            _ => {}
        }
    }

    fn target_read(&mut self, path: &[Option<&str>]) {
        let named: Option<Vec<&str>> = path.iter().copied().collect();
        let spelled = named.as_ref().map(|names| names.join("."));
        if spelled
            .as_deref()
            .is_some_and(|dotted| TARGET_SHELL_SAFE_READS.contains(&dotted))
        {
            return;
        }
        self.reads.bare.insert(match spelled {
            Some(dotted) if !dotted.is_empty() => format!("target.{dotted}"),
            _ => "target".to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::untrusted_reads_in_command;

    fn reads(source: &str) -> Vec<String> {
        let reads = untrusted_reads_in_command(source).expect("the template parses");
        reads.bare.into_iter().chain(reads.misquoted).collect()
    }

    /// Each place an untrusted read can reach the command text is refused —
    /// one cell per shape the walk names.
    #[test]
    fn an_untrusted_read_outside_a_trailing_shquote_is_named() {
        for (source, read) in [
            ("echo {{ target.pr.title }}", "target.pr.title"),
            (
                "echo {{ target.pr.title | shquote | upper }}",
                "target.pr.title",
            ),
            ("echo {{ target.pr.title ~ 'x' }}", "target.pr.title"),
            (
                "{% set t = target.pr.body %}echo {{ t | shquote }}",
                "target.pr.body",
            ),
            (
                "{% for f in target.changed_files %}{{ f.path | shquote }}{% endfor %}",
                "target.changed_files",
            ),
            (
                "{% if x %}{% else %}{{ target.branch }}{% endif %}",
                "target.branch",
            ),
            ("{{ 'a' if y else target.spec }}", "target.spec"),
            ("{{ target }}", "target"),
            ("{{ target['head'] }}", "target"),
            ("{% set t = target %}{{ t.head }}", "target"),
            ("{{ target.head.upper() }}", "target.head.upper"),
            ("{{ target.pr }}", "target.pr"),
            (
                "{% with b = target.pr.head_ref %}{{ b | shquote }}{% endwith %}",
                "target.pr.head_ref",
            ),
            (
                "{% macro m(x) %}{{ x }}{% endmacro %}{{ m(target.compare.name) }}",
                "target.compare.name",
            ),
            (
                "{% filter shquote %}{{ target.diff }}{% endfilter %}",
                "target.diff",
            ),
            ("{{ target.head[target.pr.url] }}", "target.pr.url"),
        ] {
            assert!(
                reads(source).contains(&read.to_owned()),
                "{source:?} reads {read} untrusted: {:?}",
                reads(source)
            );
        }
    }

    /// The allowed set: the safe reads anywhere, any read as the operand of a
    /// trailing `shquote`, any read in a condition.
    #[test]
    fn a_safe_quoted_or_conditional_read_is_allowed() {
        for source in [
            "git diff {{ target.compare.merge_base }} {{ target.head }}",
            "echo {{ target.kind }} {{ target.pr.number }} {{ target.diff_truncated }} {{ target.changed_files_truncated }}",
            "echo {{ target.head[:7] }}",
            "printf %s {{ target.pr.title | shquote }}",
            "printf %s {{ (target.pr.title ~ target.pr.body) | upper | shquote }}",
            "{% if target.pr and target.pr.title != '' %}echo pr{% elif target.branch %}echo b{% endif %}",
            "{{ 'pr' if target.pr.body else 'trunk' }}",
            "{% for i in [1] %}{{ target.spec | shquote }}{% endfor %}",
        ] {
            assert_eq!(reads(source), Vec::<String>::new(), "{source:?}");
        }
    }
}
