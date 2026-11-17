//! What the adapter CONTRACT refuses, and what it cannot express.
//!
//! Two kinds of assertion live here, and they are not interchangeable:
//!
//! 1. **Source-derived accounting**, the technique
//!    `crates/core/tests/operational_crash_matrix.rs` uses for its coverage
//!    claims: this file `include_str!`s the `adapter/` modules and refuses a
//!    spawn verb or a host-path type appearing in them. It is coarse by
//!    construction — it reads tokens, not types, and resolves names within one
//!    file only ([`Named`] states what it does not see) — and that is stated
//!    rather than oversold. What it CAN tell is a module that has no way to build
//!    a child process from one that does, which is the property trust boundary 4
//!    rests on.
//! 2. **Ordering proven by construction**: the issuance watermark's
//!    mark-before-act rule is a borrow-checker fact, and the rows below show the
//!    observable consequence (EOF classification) plus the source-derived fact
//!    that [`Marked`] has exactly one producer.

use kata_agent::adapter::scope::{AttemptScope, SessionSeed};
use kata_agent::adapter::session::{
    CancelToken, CleanupReport, IssuanceFrame, IssuanceWatermark, MayHaveIssued, TurnOutcome,
    act_on_marked_frame, observe_frame,
};
use kata_agent::resource_bounds::{TeardownOutcome, TeardownProbe};
use kata_types::agent::{AdapterKind, BackendType};
use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, CAPSULE_OUTPUT_BYTES, CapsuleBudgets, CapsuleId, GuestAccess,
    GuestMapping, GuestPath,
};
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const ADAPTER_MOD_SOURCE: &str = include_str!("../src/adapter/mod.rs");
const ADAPTER_SCOPE_SOURCE: &str = include_str!("../src/adapter/scope.rs");
const ADAPTER_SESSION_SOURCE: &str = include_str!("../src/adapter/session.rs");

/// What one source file NAMES, read from its Rust tokens rather than its text.
///
/// The file is lexed by `proc_macro2`, so a comment is no token at all and a
/// string literal is one opaque token: `"http://x"` hides nothing after it,
/// and a needle spelled inside a string or a doc comment is not a name. What
/// is collected, at every nesting level (macro bodies and `#[cfg]`'d-out items
/// included, since those are tokens too):
///
/// * every path `a::b::c`, with every `use` tree EXPANDED (`use tokio::{fs,
///   io};` names `tokio::fs` and `tokio::io`) and every path whose first
///   segment a `use` or an `extern crate .. as` brought in RESOLVED through
///   that import, a rename included (`use std::process::{Command as Run};
///   Run::new(..)` names `std::process::Command::new`). A path is also read
///   under every glob import's prefix (`use std::*; fs::read(..)` names
///   `std::fs::read`). The imported paths themselves resolve the same way,
///   through chains in any order (`use tokio as t; use t::fs;` names
///   `tokio::fs`, and so do `use std::*; use fs::read;` for `std::fs::read`
///   and `use tokio as t; use t::*;` under its glob), each import used at
///   most once along a chain;
/// * every identifier, a raw one (`r#fs`) read as the name it spells;
/// * every method called with an EMPTY argument list (`.output()`), WHATEVER
///   its receiver: a lexer cannot see a receiver's type, so `Command`'s
///   spawning methods and `Path`'s host-I/O methods are caught by name, and
///   any other receiver's method of that name with them.
///
/// Not seen, stated: a name a macro builds by token pasting, a path reached
/// through a type alias or a re-export defined in another file, and a method
/// called through UFCS (`Command::output(&mut c)` is still the path
/// `Command::output`, which the path needles may or may not name).
#[derive(Debug, Default)]
struct Named {
    paths: Vec<Vec<String>>,
    identifiers: std::collections::BTreeSet<String>,
    empty_calls: std::collections::BTreeSet<String>,
}

impl Named {
    fn of(source: &str) -> Self {
        let tokens: proc_macro2::TokenStream = source
            .parse()
            .expect("an adapter source lexes as Rust tokens");
        let mut uses = Uses::default();
        let mut raw_paths = Vec::new();
        let mut named = Named::default();
        named.walk(tokens, &mut uses, &mut raw_paths);
        for path in raw_paths.iter().chain(&uses.imported) {
            named.paths.extend(uses.resolutions(path));
        }
        named
    }

    fn walk(
        &mut self,
        tokens: proc_macro2::TokenStream,
        uses: &mut Uses,
        paths: &mut Vec<Vec<String>>,
    ) {
        use proc_macro2::{Delimiter, TokenTree};
        let tokens: Vec<TokenTree> = tokens.into_iter().collect();
        let mut at = 0;
        while at < tokens.len() {
            match &tokens[at] {
                TokenTree::Group(group) => {
                    self.walk(group.stream(), uses, paths);
                    at += 1;
                }
                TokenTree::Ident(ident)
                    if ident == "use"
                        || (ident == "extern"
                            && matches!(tokens.get(at + 1), Some(TokenTree::Ident(c)) if c == "crate")) =>
                {
                    let end = tokens[at..]
                        .iter()
                        .position(
                            |token| matches!(token, TokenTree::Punct(p) if p.as_char() == ';'),
                        )
                        .map_or(tokens.len(), |offset| at + offset);
                    for token in &tokens[at + 1..end] {
                        if let TokenTree::Ident(ident) = token {
                            self.identifiers.insert(name_of(ident));
                        }
                    }
                    // `extern crate std as s;` binds `s` as `use std as s;` does.
                    let tree = if ident == "use" {
                        &tokens[at + 1..end]
                    } else {
                        &tokens[(at + 2).min(end)..end]
                    };
                    uses.expand(tree, &[]);
                    at = end + 1;
                }
                TokenTree::Ident(_) => {
                    let mut segments = Vec::new();
                    let mut next = at;
                    while let Some(TokenTree::Ident(ident)) = tokens.get(next) {
                        segments.push(name_of(ident));
                        self.identifiers.insert(name_of(ident));
                        if is_path_separator(&tokens, next + 1)
                            && matches!(tokens.get(next + 3), Some(TokenTree::Ident(_)))
                        {
                            next += 3;
                        } else {
                            next += 1;
                            break;
                        }
                    }
                    let after_dot = at > 0
                        && matches!(&tokens[at - 1], TokenTree::Punct(p) if p.as_char() == '.');
                    let called_empty = matches!(
                        tokens.get(next),
                        Some(TokenTree::Group(group))
                            if group.delimiter() == Delimiter::Parenthesis
                                && group.stream().is_empty()
                    );
                    if after_dot && segments.len() == 1 && called_empty {
                        self.empty_calls.insert(segments[0].clone());
                    }
                    if !after_dot {
                        paths.push(segments);
                    }
                    at = next;
                }
                _ => at += 1,
            }
        }
    }

    /// Whether some path names `needle` as a contiguous run of segments.
    fn names_path(&self, needle: &[&str]) -> bool {
        self.paths.iter().any(|path| {
            path.windows(needle.len())
                .any(|window| window.iter().zip(needle).all(|(a, b)| a == b))
        })
    }

    /// Whether some identifier starts with `prefix`.
    fn names_identifier(&self, prefix: &str) -> bool {
        self.identifiers
            .iter()
            .any(|ident| ident.starts_with(prefix))
    }
}

/// The name `ident` spells: a raw identifier (`r#fs`) is the name `fs`.
fn name_of(ident: &proc_macro2::Ident) -> String {
    let spelled = ident.to_string();
    match spelled.strip_prefix("r#") {
        Some(name) => name.to_owned(),
        None => spelled,
    }
}

/// `::` at `tokens[at..at + 2]`.
fn is_path_separator(tokens: &[proc_macro2::TokenTree], at: usize) -> bool {
    use proc_macro2::{Spacing, TokenTree};
    matches!(
        (tokens.get(at), tokens.get(at + 1)),
        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
            if a.as_char() == ':' && a.spacing() == Spacing::Joint && b.as_char() == ':'
    )
}

/// The `use` and `extern crate` declarations of one file: every imported
/// path as written, the name each binds, and every glob prefix.
#[derive(Debug, Default)]
struct Uses {
    imported: Vec<Vec<String>>,
    /// Each bound name, with the [`Import::Bound`] index of the import that
    /// bound it last.
    bound: std::collections::BTreeMap<String, (usize, Vec<String>)>,
    globs: Vec<Vec<String>>,
}

/// One import a resolution chain stepped through: a binding, by its index in
/// [`Uses::imported`], or a glob, by its index in [`Uses::globs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Import {
    Bound(usize),
    Glob(usize),
}

/// The most spellings one path may resolve to. Past it the scan PANICS rather
/// than read a file it cannot fully resolve: the bans fail closed.
const MAX_RESOLUTIONS: usize = 4096;

impl Uses {
    /// Expand one use tree's tokens (after `use`, before `;`) under `prefix`.
    fn expand(&mut self, tokens: &[proc_macro2::TokenTree], prefix: &[String]) {
        use proc_macro2::{Delimiter, TokenTree};
        for item in tokens.split(|token| matches!(token, TokenTree::Punct(p) if p.as_char() == ','))
        {
            let mut path = prefix.to_vec();
            let mut alias = None;
            let mut nested = false;
            let mut tokens = item.iter();
            while let Some(token) = tokens.next() {
                match token {
                    TokenTree::Ident(ident) if ident == "as" => {
                        alias = match tokens.next() {
                            Some(TokenTree::Ident(alias)) => Some(name_of(alias)),
                            other => other.map(ToString::to_string),
                        };
                    }
                    TokenTree::Ident(ident) if ident == "self" => {}
                    TokenTree::Ident(ident) => path.push(name_of(ident)),
                    TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => {
                        let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                        self.expand(&inner, &path);
                        nested = true;
                    }
                    TokenTree::Punct(p) if p.as_char() == '*' => {
                        self.globs.push(path.clone());
                        nested = true;
                    }
                    _ => {}
                }
            }
            if nested || path.is_empty() {
                continue;
            }
            let name = alias.unwrap_or_else(|| path.last().cloned().unwrap_or_default());
            if name != "_" {
                self.bound.insert(name, (self.imported.len(), path.clone()));
            }
            self.imported.push(path);
        }
    }

    /// Every spelling `path` can stand for: itself, and, repeatedly, its first
    /// segment replaced by the path an import bound to it and it read under
    /// each glob prefix — each import at most once along one chain, so a cycle
    /// (`use a as b; use b as a;`) ends.
    fn resolutions(&self, path: &[String]) -> std::collections::BTreeSet<Vec<String>> {
        let mut out = std::collections::BTreeSet::new();
        let mut pending = vec![(path.to_vec(), std::collections::BTreeSet::new())];
        while let Some((path, used)) = pending.pop() {
            out.insert(path.clone());
            assert!(
                out.len() <= MAX_RESOLUTIONS,
                "the scan cannot resolve {path:?} within {MAX_RESOLUTIONS} spellings"
            );
            let bound = path.first().and_then(|first| self.bound.get(first));
            let mut steps: Vec<(Import, Vec<String>)> = bound
                .map(|(index, to)| {
                    let next = to.iter().chain(&path[1..]).cloned().collect();
                    (Import::Bound(*index), next)
                })
                .into_iter()
                .collect();
            steps.extend(self.globs.iter().enumerate().map(|(index, glob)| {
                (
                    Import::Glob(index),
                    glob.iter().chain(&path).cloned().collect(),
                )
            }));
            for (import, next) in steps {
                if !used.contains(&import) {
                    let mut used = used.clone();
                    used.insert(import);
                    pending.push((next, used));
                }
            }
        }
        out
    }
}

/// A forbidden name, as the scan matches it.
#[derive(Clone, Copy, Debug)]
enum Needle {
    /// A contiguous run of path segments, after use trees and imports resolve.
    Path(&'static [&'static str]),
    /// An identifier starting with this text, anywhere in the file.
    Identifier(&'static str),
    /// A method of this name called with no argument.
    EmptyCall(&'static str),
}

impl Needle {
    fn found_in(self, named: &Named) -> bool {
        match self {
            Self::Path(segments) => named.names_path(segments),
            Self::Identifier(prefix) => named.names_identifier(prefix),
            Self::EmptyCall(method) => named.empty_calls.contains(method),
        }
    }
}

/// The spawn ban's refused set: the `Command` type of `std::process` or
/// `tokio::process` named by any path or import (renames resolved), its
/// constructor, the `std::os::unix::process` extension trait and its
/// `pre_exec` hook, and any method named `spawn`, `output` or `status` called
/// with no argument, WHATEVER its receiver — the three ways a built `Command`
/// starts a process, caught by name where a rename hid the type, so an HTTP
/// response's `.status()` is refused with them.
const SPAWN_NEEDLES: &[Needle] = &[
    Needle::Path(&["process", "Command"]),
    Needle::Path(&["Command", "new"]),
    Needle::Identifier("pre_exec"),
    Needle::Identifier("CommandExt"),
    Needle::EmptyCall("spawn"),
    Needle::EmptyCall("output"),
    Needle::EmptyCall("status"),
];

/// The host-path ban's refused set: `PathBuf`, `std::path`, `Path::new`,
/// `std::fs` and `std::env`, each named by any path or import.
const HOST_PATH_NEEDLES: &[Needle] = &[
    Needle::Identifier("PathBuf"),
    Needle::Path(&["std", "path"]),
    Needle::Path(&["Path", "new"]),
    Needle::Path(&["std", "fs"]),
    Needle::Path(&["std", "env"]),
];

/// The nanocode host-I/O ban's refused set: the standard, tokio and rustix
/// filesystem modules and the standard environment module named by any path
/// or import; the `openat` family; `canonicalize`, `read_link` and
/// `current_dir`; building a `Path` from a string (`Path::new`); and any
/// method named as one of `Path`'s host-I/O methods (`exists`, `try_exists`,
/// `metadata`, `symlink_metadata`, `read_dir`, `is_file`, `is_dir`) called with
/// no argument, WHATEVER its receiver: the scan cannot see a receiver's type,
/// so a `job.is_file()` is refused with `path.is_file()`.
const HOST_IO_NEEDLES: &[Needle] = &[
    Needle::Path(&["std", "fs"]),
    Needle::Path(&["std", "env"]),
    Needle::Path(&["tokio", "fs"]),
    Needle::Path(&["rustix", "fs"]),
    Needle::Identifier("openat"),
    Needle::Identifier("canonicalize"),
    Needle::Identifier("read_link"),
    Needle::Identifier("current_dir"),
    Needle::Path(&["Path", "new"]),
    Needle::EmptyCall("exists"),
    Needle::EmptyCall("try_exists"),
    Needle::EmptyCall("metadata"),
    Needle::EmptyCall("symlink_metadata"),
    Needle::EmptyCall("read_dir"),
    Needle::EmptyCall("is_file"),
    Needle::EmptyCall("is_dir"),
];

/// The needles of `set` that `source` names.
fn violations(source: &str, set: &[Needle]) -> Vec<Needle> {
    let named = Named::of(source);
    set.iter()
        .copied()
        .filter(|needle| needle.found_in(&named))
        .collect()
}

/// Every source file the spawn/host-path ban covers, with the name a failure
/// should print: the contract under `adapter/` (the one adapter kata ships,
/// nanocode's, is scanned from its own crate by [`NANOCODE_SOURCES`]). The
/// list is written out rather than walked, so
/// adding a module is a decision somebody records here.
const ADAPTER_SOURCES: &[(&str, &str)] = &[
    ("adapter/mod.rs", ADAPTER_MOD_SOURCE),
    ("adapter/scope.rs", ADAPTER_SCOPE_SOURCE),
    ("adapter/session.rs", ADAPTER_SESSION_SOURCE),
];

/// The embedded nanocode harness's adapter, in `kata-agent-nanocode`: read as
/// SOURCE by path at run time, never built — kata-agent's tests do not compile
/// nanocode — and held to the same bans, because the ban is on the adapter
/// wherever it lives. Every file under that crate's `src/` is scanned except
/// [`NANOCODE_HOST_SIDE`], which the pin below names.
const NANOCODE_SOURCES: &[&str] = &[
    "lib.rs",
    "adapter/mod.rs",
    "adapter/session.rs",
    "adapter/seam.rs",
    "adapter/toolhost_client.rs",
    "adapter/events.rs",
];

/// The one host-side module the nanocode crate may carry, outside the scan by
/// name: `credential.rs` loads kata's own login file into nanocode's auth on
/// the HOST, before any capsule exists. It does not exist yet; the pin below
/// fails the moment any OTHER file appears unscanned.
const NANOCODE_HOST_SIDE: &str = "credential.rs";

/// The file of the nanocode adapter that names `std::path::Path`: nanocode's
/// host traits are `Path`-typed, so the seam cannot avoid the type. It is held
/// instead to [`no_nanocode_module_can_do_host_io`]'s needle set alone.
const NANOCODE_SEAM: &str = "adapter/seam.rs";

/// `kata-agent-nanocode/src/<relative>`, read off the filesystem.
fn nanocode_source(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-nanocode/src")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// Every source the spawn ban covers: kata-agent's own adapter files and every
/// scanned nanocode file, by the name a failure prints.
fn spawn_ban_sources() -> Vec<(String, String)> {
    ADAPTER_SOURCES
        .iter()
        .map(|(name, source)| ((*name).to_owned(), (*source).to_owned()))
        .chain(
            NANOCODE_SOURCES
                .iter()
                .map(|name| (format!("agent-nanocode/src/{name}"), nanocode_source(name))),
        )
        .collect()
}

/// Every source the host-path ban covers: the spawn ban's set minus the seam.
fn host_path_ban_sources() -> Vec<(String, String)> {
    spawn_ban_sources()
        .into_iter()
        .filter(|(name, _)| name != &format!("agent-nanocode/src/{NANOCODE_SEAM}"))
        .collect()
}

// ── 1. what the adapter layer cannot express --------------------------------

/// No adapter module may name a process-spawning verb: [`SPAWN_NEEDLES`],
/// matched by [`Named`] in every file of [`spawn_ban_sources`].
///
/// # Every needle is load-bearing, and here is what each one catches
///
/// `process::Command` catches both `std::process::Command` and
/// `tokio::process::Command`, written inline or imported, grouped or renamed.
/// `Command::new` catches a bare `Command` brought in by a glob, and a rename
/// once it resolves. `spawn()`, `output()` and `status()` catch a `Command`
/// whose type name never appears (`let c: Vendor = ..; c.output()`), and
/// `spawn()` also its async siblings. `pre_exec` and `CommandExt` catch the
/// `std::os::unix::process` extension trait, which is how a spawn acquires the
/// pre-exec hook that would place a child OUTSIDE the capsule — the specific
/// outcome trust boundary 4 forbids — without the word `Command` appearing near
/// it. A call with arguments (`runtime.spawn(task)`, a tokio task) is not a
/// spawn of a process and is not refused; an empty-argument call of one of the
/// three names is refused on any receiver, a `Command` or not.
#[test]
fn no_adapter_module_can_build_a_command() {
    for (name, source) in spawn_ban_sources() {
        let found = violations(&source, SPAWN_NEEDLES);
        assert!(
            found.is_empty(),
            "{name} names {found:?}: an adapter must NEVER build a process — it \
             receives a running one as an `InteractiveProcess` the worker placed inside the \
             capsule (ADR-0001 trust boundary 4)"
        );
    }
}

/// No module under `adapter/` may name a HOST path type: [`HOST_PATH_NEEDLES`]
/// in every file of [`host_path_ban_sources`].
///
/// `AttemptScope` carries `GuestPath` only; a `PathBuf` field, parameter or local
/// would be the first step to an adapter resolving a host path itself. Matching
/// paths by SEGMENT is what keeps `GuestPath::new` — the exact call this layer
/// requires to turn a vendor's string into a path — from reading as
/// `Path::new`.
#[test]
fn no_adapter_module_can_name_a_host_path() {
    for (name, source) in host_path_ban_sources() {
        let found = violations(&source, HOST_PATH_NEEDLES);
        assert!(
            found.is_empty(),
            "{name} names {found:?}: the adapter layer's only path vocabulary is \
             `GuestPath`, so a host path must not be expressible here"
        );
    }
}

/// No nanocode adapter file may do HOST I/O, the seam included. The seam is
/// the one adapter file that must name `std::path::Path`, because nanocode's
/// `ShellExecutor`, `FileHost` and `ForegroundExecutor` are `Path`-typed, so
/// the host-path ban above cannot apply to it; a `Path` there is only ever
/// stringified onto the toolhost wire and resolved by the capsule's mount
/// namespace. The other nanocode files are under the host-path ban AND this
/// set, because the host-path ban does not name tokio's or rustix's
/// filesystem modules. The refused set, in every file of
/// [`NANOCODE_SOURCES`], is [`HOST_IO_NEEDLES`]: the standard and tokio
/// filesystem modules, rustix's, the `openat` family, path resolution against
/// the host (`canonicalize`, `read_link`, `current_dir`), the environment,
/// building a fresh `Path` from a string (`Path::new`), which only a host
/// lookup would need, and an empty-argument call of any method named as one of
/// `Path`'s host-I/O methods, on any receiver. Matched by [`Named`], like the
/// other two bans.
#[test]
fn no_nanocode_module_can_do_host_io() {
    for name in NANOCODE_SOURCES {
        let found = violations(&nanocode_source(name), HOST_IO_NEEDLES);
        assert!(
            found.is_empty(),
            "agent-nanocode/src/{name} names {found:?}: the nanocode adapter answers \
             nanocode's host traits over the toolhost wire and never touches the host"
        );
    }
}

/// **The scanner refuses each form its doc names, and passes what it must.**
/// Each bypass the text scan it replaced let through is refused by the ban it
/// belongs to: grouped `fs` and `env` imports, a renamed `Command` calling
/// `.output()`, a glob import of `std`, a `//` inside a string literal ahead of
/// `std::fs::read` on the same line, and `path.exists()`. So is each import
/// chain [`Named`] resolves: a `use` starting at a name another `use` bound, in
/// either order; a `use` under a glob; a glob of a renamed crate; an `extern
/// crate .. as` alias; and a raw identifier, in a path or a use tree. An
/// empty-argument call of a needle's method name is refused on any receiver,
/// which is the stated set: `job.is_file()` and an HTTP response's `.status()`.
/// And what the layer must keep writing is not refused: `GuestPath::new`, a
/// tokio task's `runtime.spawn(task)`, and a needle spelled only in a comment or
/// a string.
///
/// **Would red if:** use trees stopped being expanded or resolved (an imported
/// path's first segment included), `extern crate` aliases or `r#` were not
/// read, string literals hid code again, or a needle matched across a segment
/// boundary.
#[test]
fn the_ban_scanner_refuses_each_stated_form_and_nothing_wider() {
    let refused = |source: &str, set: &[Needle]| !violations(source, set).is_empty();
    let mut wrong = Vec::new();
    for (form, source, set) in [
        (
            "grouped tokio::fs",
            "use tokio::{fs, io}; fn f(p: &P) { let _ = fs::metadata(p); }",
            HOST_IO_NEEDLES,
        ),
        (
            "grouped std::env",
            "use std::{env, io}; fn f() { let _ = env::var(\"X\"); }",
            HOST_IO_NEEDLES,
        ),
        (
            "renamed Command calling output()",
            "use std::process::{Command as Run}; fn f() { let _ = Run::new(\"x\").output(); }",
            SPAWN_NEEDLES,
        ),
        (
            "a glob import of std",
            "use std::*; fn f() { let _ = fs::read(\"x\"); }",
            HOST_IO_NEEDLES,
        ),
        (
            "// inside a string, then std::fs::read",
            "fn f() { let _ = \"http://x\"; let _ = std::fs::read(\"y\"); }",
            HOST_IO_NEEDLES,
        ),
        (
            "path.exists()",
            "fn f(path: &Path) -> bool { path.exists() }",
            HOST_IO_NEEDLES,
        ),
        (
            "a renamed Command calling status() through a binding",
            "use tokio::process::Command as Vendor; fn f(mut c: Vendor) { let _ = c.status(); }",
            SPAWN_NEEDLES,
        ),
        (
            "a use starting at a name another use bound",
            "use tokio as t; use t::fs; fn f(p: &P) { let _ = fs::metadata(p); }",
            HOST_IO_NEEDLES,
        ),
        (
            "a use starting at a name a LATER use binds",
            "use t::fs; use tokio as t; fn f(p: &P) { let _ = fs::metadata(p); }",
            HOST_IO_NEEDLES,
        ),
        (
            "a use under a glob",
            "use std::*; use fs::read; fn f() { let _ = read(\"x\"); }",
            HOST_IO_NEEDLES,
        ),
        (
            "a glob of a renamed crate",
            "use tokio as t; use t::*; fn f(p: &P) { let _ = fs::metadata(p); }",
            HOST_IO_NEEDLES,
        ),
        (
            "an extern crate alias",
            "extern crate std as s; fn f() { let _ = s::fs::read(\"x\"); }",
            HOST_IO_NEEDLES,
        ),
        (
            "a raw identifier in a path",
            "fn f() { let _ = std::r#fs::read(\"x\"); }",
            HOST_IO_NEEDLES,
        ),
        (
            "a raw identifier in a use tree, renamed",
            "use std::process::{r#Command as Run}; fn f() { let _ = Run::new(\"x\"); }",
            SPAWN_NEEDLES,
        ),
        (
            "is_file() on a receiver that is not a Path",
            "fn f(job: &Job) -> bool { job.is_file() }",
            HOST_IO_NEEDLES,
        ),
        (
            "status() on a receiver that is not a Command",
            "fn f(response: &Response) -> u16 { response.status() }",
            SPAWN_NEEDLES,
        ),
    ] {
        if !refused(source, set) {
            wrong.push(format!("must refuse {form}: {source}"));
        }
    }
    for (form, source, set) in [
        (
            "GuestPath::new",
            "fn f(x: &str) { let _ = GuestPath::new(x); }",
            HOST_PATH_NEEDLES,
        ),
        (
            "a tokio task's spawn(task)",
            "fn f(runtime: &R) { drop(runtime.spawn(async move {})); }",
            SPAWN_NEEDLES,
        ),
        (
            "needles in a comment and a string",
            "// std::fs::read(p); Command::new(x).output()\nfn f() { let _ = \"std::fs\"; }",
            HOST_IO_NEEDLES,
        ),
    ] {
        if refused(source, set) {
            wrong.push(format!("must not refuse {form}: {source}"));
        }
    }
    assert!(wrong.is_empty(), "the scanner:\n{}", wrong.join("\n"));
}

/// **The nanocode scan covers every file but the one host-side module.** Every
/// `.rs` file under `kata-agent-nanocode/src/` is either in
/// [`NANOCODE_SOURCES`] or is [`NANOCODE_HOST_SIDE`], read off the filesystem:
/// a new adapter file that is not added to the scan fails here instead of
/// escaping it, and so does a second host-side module.
#[test]
fn every_nanocode_source_but_the_host_side_one_is_scanned() {
    fn walk(dir: &std::path::Path, root: &std::path::Path, into: &mut Vec<String>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, into);
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
                let relative = path.strip_prefix(root).expect("under the root");
                into.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../agent-nanocode/src");
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    found.sort();
    let unscanned: Vec<&String> = found
        .iter()
        .filter(|file| !NANOCODE_SOURCES.contains(&file.as_str()) && *file != NANOCODE_HOST_SIDE)
        .collect();
    assert!(
        unscanned.is_empty(),
        "agent-nanocode/src files outside the adapter scan: {unscanned:?}; only \
         `{NANOCODE_HOST_SIDE}` may be"
    );
    for listed in NANOCODE_SOURCES {
        assert!(
            found.iter().any(|file| file == listed),
            "the scan lists `{listed}`, which does not exist: {found:?}"
        );
    }
}

/// [`Marked`] has exactly ONE producer, and it is the function that sets the
/// watermark.
///
/// The compile-time fact (a private field, no public constructor, no `Clone`) is
/// what actually enforces the ordering; this row is the source-derived companion
/// that fails if a second producer is added, since a second producer is exactly
/// how the mark-before-act ordering would be lost without any call site changing.
#[test]
fn marked_has_one_producer_and_it_marks_first() {
    let producers = ADAPTER_SESSION_SOURCE.matches("-> Marked {").count();
    assert_eq!(
        producers, 1,
        "`Marked` must have exactly one producer (`observe_frame`); found {producers} functions \
         returning it, so the mark-before-act ordering may no longer be guaranteed"
    );
    let body = ADAPTER_SESSION_SOURCE
        .split("pub fn observe_frame")
        .nth(1)
        .expect("observe_frame is the producer");
    let head = &body[..body.len().min(400)];
    assert!(
        head.contains("watermark.crossed = Some("),
        "observe_frame must SET the watermark before handing out a token; body read: {head}"
    );
    assert!(
        !ADAPTER_SESSION_SOURCE.contains("derive(Clone")
            || !ADAPTER_SESSION_SOURCE
                .split("pub struct Marked")
                .next()
                .expect("head")
                .rsplit("#[derive(")
                .next()
                .expect("derive")
                .contains("Clone"),
        "`Marked` must not be Clone: a cloned token could authorize acting on a LATER frame \
         under an EARLIER frame's mark"
    );
}

// ── 2. the watermark's observable consequence -------------------------------

/// EOF BEFORE the watermark is provably-nothing-issued; EOF AFTER it is
/// ambiguous, and names what may have gone out.
#[test]
fn the_watermark_decides_the_eof_outcome() {
    let clean = IssuanceWatermark::clean();
    assert!(clean.is_clean());
    assert_eq!(clean.crossed(), None);
    assert!(
        matches!(
            clean.eof_outcome("pipe closed"),
            TurnOutcome::Cancelled { usage: None }
        ),
        "EOF before the watermark must not be an ambiguity"
    );

    for (frame, expected) in [
        (IssuanceFrame::ModelToken, MayHaveIssued::ModelTokens),
        (IssuanceFrame::ToolCall, MayHaveIssued::ToolCall),
        (
            IssuanceFrame::PermissionRequest,
            MayHaveIssued::PermissionGrant,
        ),
    ] {
        let mut watermark = IssuanceWatermark::clean();
        // The ONLY way to obtain the token that authorizes acting on the frame.
        let marked = observe_frame(&mut watermark, frame);
        assert!(
            !watermark.is_clean(),
            "the watermark must be set BEFORE the act, i.e. by the time a token exists"
        );
        assert_eq!(act_on_marked_frame(&marked), frame);
        assert_eq!(watermark.crossed(), Some(expected));

        let outcome = watermark.eof_outcome("vendor stdout closed mid-frame");
        let TurnOutcome::Ambiguous { issued, evidence } = &outcome else {
            panic!("EOF after the watermark must be Ambiguous, got {outcome:?}");
        };
        assert_eq!(*issued, expected);
        assert_eq!(evidence, "vendor stdout closed mid-frame");
    }
}

/// The watermark is MONOTONIC: a later, heavier frame does not overwrite the
/// first crossing.
#[test]
fn the_watermark_records_the_first_crossing_only() {
    let mut watermark = IssuanceWatermark::clean();
    let _first = observe_frame(&mut watermark, IssuanceFrame::ModelToken);
    let _second = observe_frame(&mut watermark, IssuanceFrame::ToolCall);
    assert_eq!(
        watermark.crossed(),
        Some(MayHaveIssued::ModelTokens),
        "the honest evidence is where the session STOPPED being provably clean"
    );
}

/// The token every `prompt` races: `cancel()` flips exactly what
/// `is_cancelled()` answers, and only after it fires.
#[test]
fn a_cancel_token_reports_only_after_it_fires() {
    let token = CancelToken::new();
    assert!(
        !token.is_cancelled(),
        "an unfired token must not read as cancelled"
    );
    token.cancel();
    assert!(
        token.is_cancelled(),
        "the fired token reads as cancelled — a no-op `cancel()` is a cancel \
         kata believes it sent and never did"
    );
}

// ── 3. a turn's cleanup report ------------------------------------------------

/// A `CleanupReport` never converts an unconfirmed teardown into a success.
#[test]
fn cleanup_report_carries_the_teardown_verbatim() {
    let confirmed = CleanupReport::new(
        TeardownOutcome::Confirmed {
            probe: TeardownProbe::CgroupPopulation,
            elapsed_ms: 12,
        },
        true,
    );
    assert!(confirmed.is_confirmed());
    assert!(confirmed.harness_acknowledged_cancel());

    let ambiguous = CleanupReport::new(
        TeardownOutcome::Ambiguous {
            reason: kata_agent::resource_bounds::AmbiguousTeardown::NoGroupCaptured,
            elapsed_ms: 5_000,
        },
        true,
    );
    assert!(
        !ambiguous.is_confirmed(),
        "a harness that acknowledged a cancel is NOT evidence its process is gone"
    );
}

/// The scope hands an adapter guest paths and budgets, and nothing else.
///
/// The type-level half of this is that `AttemptScope` has no host-path field; the
/// observable half is that every path it yields is a `GuestPath`, which by its own
/// constructor is under a guest root.
#[test]
fn the_attempt_scope_exposes_guest_paths_only() {
    let artifact = ArtifactRef::new(
        object_id_for_canonical_bytes(b"{\"tree\":\"work\"}"),
        4_096,
        ArtifactPrivacy::Public,
    )
    .id();
    let mappings = vec![
        GuestMapping {
            artifact,
            guest_path: GuestPath::new("/work").expect("/work is a guest root"),
            access: GuestAccess::ReadWrite,
        },
        GuestMapping {
            artifact,
            guest_path: GuestPath::new("/out/report.json").expect("under /out"),
            access: GuestAccess::ReadOnly,
        },
    ];
    let attempt = Ulid::new();
    let scope = AttemptScope::new(
        attempt,
        SessionSeed::new(ContentHash::new([7_u8; 32])),
        mappings,
        CapsuleBudgets {
            wall_time_ms: 60_000,
            output_bytes: CAPSULE_OUTPUT_BYTES,
            memory_bytes: 2 << 30,
            process_count: 64,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        CapsuleId(ContentHash::new([9_u8; 32])),
        kata_types::redaction::LiftedSecrets::none(),
    );

    assert_eq!(scope.attempt_id(), attempt);
    let paths: Vec<&str> = scope.guest_paths().map(GuestPath::as_str).collect();
    assert_eq!(paths, vec!["/work", "/out/report.json"]);
    assert_eq!(scope.budgets().output_bytes, CAPSULE_OUTPUT_BYTES);
    // A host path is not constructible as a mapping at all — the refusal lives in
    // `GuestPath::new`, and this row shows the adapter layer inherits it.
    assert!(GuestPath::new("/home/alice/.codex").is_err());
    assert!(GuestPath::new("/work/../etc/passwd").is_err());
}

// ── 4. the dispatch key is parallel to BackendType --------------------------

/// Every [`AdapterKind`] round-trips its label, and no [`BackendType`] label
/// resolves to one (nor the reverse).
#[test]
fn adapter_kind_labels_round_trip_and_do_not_alias_backend_labels() {
    for kind in AdapterKind::ALL {
        assert_eq!(
            AdapterKind::from_label(kind.as_label()),
            Some(kind),
            "{} must round-trip",
            kind.as_label()
        );
        assert_eq!(
            BackendType::from_label(kind.as_label()),
            None,
            "{} must not also name a routing backend",
            kind.as_label()
        );
    }
    for backend in [
        BackendType::Harness,
        BackendType::Shell,
        BackendType::WorkspaceEffect,
    ] {
        assert_eq!(
            AdapterKind::from_label(backend.label()),
            None,
            "{} is a routing label, not an adapter contract",
            backend.label()
        );
    }
    assert_eq!(AdapterKind::from_label("nanocode_openai_v2"), None);
    assert_eq!(AdapterKind::from_label("codex_app_server"), None);
    assert_eq!(AdapterKind::from_label(""), None);
    assert_eq!(
        AdapterKind::ALL.len(),
        2,
        "ADR-0001 admits one agent contract, the embedded nanocode harness, as two kinds, one \
         per model provider; a contract outside the ADR needs an ADR, not a variant"
    );
}
