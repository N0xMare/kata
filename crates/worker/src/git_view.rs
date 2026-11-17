//! The agent capsule's DISPOSABLE GIT VIEW: a real, writable
//! repository the container sees at `/work`'s `.git`, assembled entirely from
//! CAS bytes and never from the host's repository.
//!
//! # The layout this module builds, beneath the attempt root
//!
//! * `git-history/` — the history tree artifact ([`CapsuleGitView::history`]),
//!   materialized through the same verified-member machinery as every input.
//!   Its members spell a git object store's innards: `objects/pack/pack-*.{pack,idx}`,
//!   `index`, and `shallow` when the producer depth-limited. The bundle mounts
//!   it at `/git-history` READ-ONLY — the agent's commits can never touch it.
//! * `git/` — the per-attempt WRITABLE git directory. `HEAD` and both refs
//!   point at the base commit; `objects/info/alternates` reaches the history
//!   mount by a RELATIVE path — see [`ALTERNATES`]; `index` and `shallow` are
//!   COPIED out of the history mount, because git rewrites both on the first
//!   `status` and a read-only file where git expects a writable one reports
//!   corruption rather than a repository.
//! * `work/.git` — the gitfile `gitdir: /git`, written AFTER `/work` is
//!   materialized, so the agent's tools detect the repository the moment they
//!   walk the tree.
//!
//! # What this module never does
//!
//! It never opens the host repository — every byte arrives through the
//! artifact the capsule names. It never mounts `/git` or `/git-history` into
//! the delta's view — `work_delta`'s walk sees `/work` only, and the gitfile
//! is excluded there by construction. The scratch history is NEVER
//! adopted: [`scratch_commits`] reads it for evidence after the turn, and the
//! attempt root's teardown removes it. And that host-side read never lets the
//! guest's bytes choose what it opens: the guest had `/git` read-write, so
//! [`scratch_commits`] admits the tree (directories and regular files only, no
//! `commondir`, no packs, bounded control files), reasserts the `config` and
//! alternates line this module wrote, ignores replace refs, refuses a symbolic
//! scratch ref, and bounds every object it decodes.
//!
//! # The scratch ref name
//!
//! `refs/heads/kata/<execution-id>` — the execution's own ulid, spelled by the
//! caller from the dispatch frame. `HEAD` points at it, the base branch's
//! short name sits beside it at the same base commit (so `git diff main` and
//! `git log main..` answer), and [`scratch_commits`] reads it back to bound
//! the commit evidence.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use bstr::ByteSlice as _;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::CapsuleGitView;
use kata_types::scratch_commit::ScratchCommitReport;

use crate::materialize::{BlobSource, Dir, TreeResolver, materialize_tree};

/// The attempt-root subdirectory that backs the guest's read-only `/git-history`.
pub const HISTORY_ROOT_NAME: &str = "git-history";
/// The attempt-root subdirectory that backs the guest's writable `/git`.
pub const SCRATCH_ROOT_NAME: &str = "git";

/// The bound on commits the evidence walk records — the scratch history is
/// evidence, not plumbing, so the row count is capped rather than grown with
/// whatever the agent wrote.
pub const MAX_SCRATCH_COMMITS: usize = 32;
/// The bound on parents one report carries — an octopus merge past it records
/// a COUNT in `parents_dropped`, not a silently shortened list.
pub const SCRATCH_COMMIT_PARENT_LIMIT: usize = 8;

/// `HEAD`'s target and the ref the evidence reader walks —
/// `refs/heads/kata/<execution-id>`. The name is the worker's own plumbing
/// (the capsule never carries it), unique per execution by the id it spells,
/// and the ONE derivation [`materialize_git_view`] writes and
/// [`scratch_commits`] reads.
#[must_use]
pub fn scratch_ref_name(execution: ulid::Ulid) -> String {
    format!("refs/heads/kata/{execution}")
}

/// The two host roots a git-view capsule's bundle binds — the materialized
/// history beside the writable scratch, derived from one attempt root so the
/// render cannot pair directories that disagree about which attempt they serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitViewLayout {
    /// `<attempt_root>/git-history` — materialized, mounted `ro` at `/git-history`.
    pub history: PathBuf,
    /// `<attempt_root>/git` — configured, mounted `rw` at `/git`.
    pub scratch: PathBuf,
}

/// The gitfile `/work/.git` carries — the guest spelling of the scratch dir,
/// which is a mount point rather than a host path precisely so the view never
/// leaks a host fact into the container.
const GITFILE: &[u8] = b"gitdir: /git\n";

/// The alternates line — RELATIVE to the object directory it lives in, which
/// is the load-bearing choice the absolute `/git-history/objects` could not
/// make: the same file then spells the same answer inside the guest
/// (`/git/objects/../../git-history/objects`) and on the host
/// (`<root>/git/objects/../../git-history/objects`), where
/// [`scratch_commits`] reads the scratch repo back through `gix`. Measured:
/// git resolves an alternates line against the object directory, and — the
/// half that rules the absolute spelling out — a MISSING alternates entry is
/// not ignored but is a `unable to normalize alternate object path` error, so
/// the guest's own absolute path would break the host-side evidence read.
const ALTERNATES: &[u8] = b"../../git-history/objects\n";

fn refused(reason: impl std::fmt::Display) -> KataError {
    KataError::Validation(format!("git_view refused: {reason}"))
}

fn io_refused(reason: &str, error: &impl std::fmt::Display) -> KataError {
    KataError::Storage(format!("git_view refused: {reason}: {error}"))
}

/// Materialize `view` beneath `attempt_root`: the history artifact at
/// `git-history/`, the configured scratch git dir at `git/`, and the
/// `/work/.git` gitfile — in that order, so a refusal leaves no half-built
/// view behind that a reader could mistake for assembled.
///
/// # Refused set
///
/// * `git_view_base_commit_malformed` — `base_commit`, or the branch ref's
///   commit, is not a lowercase hex object id of 40 or 64 digits;
/// * `git_view_branch_invalid` — the branch ref's name does not parse as a git
///   branch name under `refs/heads/` (this is the escape check: `../x` would
///   otherwise climb out of `refs/`);
/// * `git_view_base_unresolvable` — the history does not hold the base commit
///   or the branch ref's commit as a commit;
/// * `git_view_history_lacks_index` — the history artifact carried no `index`
///   member, which would boot the view with every tracked file "untracked";
/// * the artifact's own resolution, member-size and write refusals (the
///   materializer's), and any filesystem refusal — each naming its path.
///
/// # Errors
/// [`KataError::Validation`] for the refused set, [`KataError::Storage`] for
/// filesystem failures.
pub fn materialize_git_view(
    view: &CapsuleGitView,
    trees: &dyn TreeResolver,
    source: &dyn BlobSource,
    attempt_root: &Path,
    execution: ulid::Ulid,
) -> KataResult<GitViewLayout> {
    // The two claims the capsule carries that this function must check before a
    // byte is placed: the commit id must BE a commit id's spelling (the scratch
    // refs are written as loose-ref text — a non-hex payload would boot the view
    // into a state git reports as corrupt rather than absent), and the branch
    // name must be a REAL ref name, because `refs/heads/<branch>` with a `..`
    // inside it is a path escape into wherever the attempt root's parent is.
    let base = checked_base_commit(&view.base_commit)?;
    let branch = view
        .branch
        .as_ref()
        .map(|branch| {
            Ok::<_, KataError>((
                checked_branch_ref(&branch.name)?,
                checked_base_commit(&branch.commit)?,
            ))
        })
        .transpose()?;

    let root =
        Dir::open(attempt_root).map_err(|error| io_refused("open the attempt root", &error))?;
    // FRESH, like the materializer's own children: a `git-history` or `git`
    // already present is a previous attempt's tree, and `create_child`'s EEXIST
    // is the refusal rather than the reuse.
    let history = root.create_child(HISTORY_ROOT_NAME, 0o755)?;
    // No view: the history artifact materializes whole — it is the capsule's
    // own declared object, not a confined read.
    materialize_tree(&history, view.history.id(), trees, source, None)?;

    let scratch = root.create_child(SCRATCH_ROOT_NAME, 0o755)?;
    write_scratch(&scratch, &history, view, execution, branch.as_ref(), &base)?;
    verify_base_resolves(&scratch, &base)?;
    if let Some((_, branch_commit)) = &branch {
        verify_base_resolves(&scratch, branch_commit)?;
    }

    // The gitfile — AFTER the scratch exists, so `/work` never carries a pointer
    // at a half-assembled repository.
    let work = Dir::open(&attempt_root.join("work"))
        .map_err(|error| io_refused("open the materialized /work", &error))?;
    work.write_file(".git", 0o644, GITFILE)?;

    Ok(GitViewLayout {
        history: attempt_root.join(HISTORY_ROOT_NAME),
        scratch: attempt_root.join(SCRATCH_ROOT_NAME),
    })
}

/// `base_commit` as a lowercase hex object id — 40 hexits (sha1) or 64
/// (sha256). Anything else is refused before it becomes a loose ref's content:
/// the capsule is kata-produced, and a corrupt one should fail HERE, with a
/// named refusal, rather than boot a repository git calls corrupt.
fn checked_base_commit(base: &str) -> KataResult<String> {
    let hex = (base.len() == 40 || base.len() == 64)
        && base
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if hex {
        Ok(base.to_owned())
    } else {
        Err(refused(format!(
            "git_view_base_commit_malformed: the capsule's base commit `{base}` is not a \
             lowercase hex object id (40 or 64 digits) — a corrupt capsule fails at the door, \
             not inside the guest's repository"
        )))
    }
}

/// The base commit the scratch refs just written NAME must resolve to a
/// commit — checked through the assembled repository itself, so the verdict
/// exercises the alternates line and the history packs, not a side read of
/// the artifact. A history that does not contain the base is refused here:
/// the refs would dangle, and the guest's first `git status` would report a
/// corrupt repository where a named refusal belonged.
fn verify_base_resolves(scratch: &Dir, base: &str) -> KataResult<()> {
    let repo = gix::open(scratch.display()).map_err(|error| {
        KataError::Storage(format!(
            "git_view refused: the scratch repository just assembled at {} does not open: {error}",
            scratch.display().display()
        ))
    })?;
    let object = repo
        .find_object(gix::ObjectId::from_hex(base.as_bytes()).expect("checked_base_commit"))
        .map_err(|error| {
            refused(format!(
                "git_view_base_unresolvable: the history artifact does not contain the base \
                 commit `{base}` — the refs written over it would dangle, so the capsule is \
                 refused here rather than booting a repository git reports as corrupt ({error})"
            ))
        })?;
    if object.kind != gix::object::Kind::Commit {
        return Err(refused(format!(
            "git_view_base_unresolvable: the object the capsule names as base commit `{base}` \
             is a {} — a commit id is the only honest answer",
            object.kind
        )));
    }
    Ok(())
}

/// `branch` as a full `refs/heads/` name, checked against git's own ref format
/// — the traversal check (`..` cannot appear), the control-character check and
/// the reserved-sequence checks in one call rather than a hand-rolled subset.
fn checked_branch_ref(branch: &str) -> KataResult<String> {
    let full = format!("refs/heads/{branch}");
    gix::validate::reference::name(full.as_bytes().as_bstr()).map_err(|error| {
        refused(format!(
            "git_view_branch_invalid: the capsule's base branch `{branch}` is not a git ref name \
             under refs/heads/ ({error}) — a name with `..` in it is a path escape, so the check \
             is git's own validator and not a prefix test"
        ))
    })?;
    Ok(full)
}

/// A git-config value's one-way escaping: `\` → `\\`, `"` → `\"`, newline →
/// `\n`, tab → `\t` — the escapes git's own parser reads — so an inherited
/// identity string needs no refusal surface of its own.
fn config_escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

/// Populate the fresh scratch dir: refs at the base commit, HEAD at the
/// scratch branch, the alternates line, the copied index (and `shallow` when
/// the artifact carries one), and the config the design fixes.
fn write_scratch(
    scratch: &Dir,
    history: &Dir,
    view: &CapsuleGitView,
    execution: ulid::Ulid,
    branch: Option<&(String, String)>,
    base: &str,
) -> KataResult<()> {
    scratch.write_file(
        "HEAD",
        0o644,
        format!("ref: {}\n", scratch_ref_name(execution)).as_bytes(),
    )?;
    let heads = scratch
        .ensure_child("refs", 0o755)?
        .ensure_child("heads", 0o755)?;
    // HEAD names the scratch ref at the base commit; the target's branch ref
    // sits at ITS commit — trunk at the base, a pull request's base branch at
    // the compare base — so `git log main..` and `git diff main` answer the
    // way they would in the operator's own checkout.
    write_ref(&heads, &format!("kata/{execution}"), base)?;
    if let Some((branch_ref, branch_commit)) = branch {
        let name = branch_ref
            .strip_prefix("refs/heads/")
            .expect("checked_branch_ref's prefix");
        write_ref(&heads, name, branch_commit)?;
    }

    // The object store: EMPTY but for the alternates line. Loose objects and
    // packs the agent writes land here; the history they resolve against lives
    // on the read-only mount.
    let objects = scratch.ensure_child("objects", 0o755)?;
    objects.ensure_child("pack", 0o755)?;
    objects
        .ensure_child("info", 0o755)?
        .write_file("alternates", 0o644, ALTERNATES)?;

    // The INDEX is the history artifact's, COPIED — git rewrites it on the
    // first status, and a read-only index where git expects a writable one is
    // a corrupt-repo error rather than a repository. `shallow` rides along
    // when depth-limited: git reads it out of the gitdir, not the object store.
    if !copy_member(history, scratch, "index")? {
        return Err(refused(
            "git_view_history_lacks_index: the history artifact carries no `index` member, so the \
             view would boot with every tracked file untracked — `git status` dirty before the \
             agent typed a word. A history without an index is not the artifact kata \
             produces, and admitting it would report a broken capsule as a working repository",
        ));
    }
    copy_member(history, scratch, "shallow")?;

    scratch.write_file("config", 0o644, scratch_config(view, base).as_bytes())?;
    Ok(())
}

/// The scratch repository's `config`, the ONE derivation [`write_scratch`]
/// writes and [`scratch_commits`] reasserts before its read.
///
/// The OBJECT FORMAT is the base commit's own: a 64-hex base means the history
/// packs are sha256 objects, and a `repositoryformatversion = 0` config would
/// make every one of them unreadable — the scratch repository must declare the
/// format its alternates serve. sha256 repositories are
/// `repositoryformatversion = 1` with the format named under `extensions`;
/// version 0 configs do not read extensions.
fn scratch_config(view: &CapsuleGitView, base: &str) -> String {
    let object_format = match base.len() {
        40 => "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        _ => {
            "[core]\n\trepositoryformatversion = 1\n\tbare = false\n\
             [extensions]\n\tobjectformat = sha256\n"
        }
    };
    format!(
        "{object_format}\
         [gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n\
         [user]\n\tname = \"{}\"\n\temail = \"{}\"\n",
        config_escaped(view.identity.name.as_str()),
        config_escaped(view.identity.email.as_str()),
    )
}

/// Write a loose ref `name` (relative to `refs/heads/`, already validated) at
/// `oid`, descending `ensure_child` for each ancestor component — a nested
/// branch like `release/1.2` spells directories.
fn write_ref(heads: &Dir, name: &str, oid: &str) -> KataResult<()> {
    let mut dir = heads
        .reopen()
        .map_err(|error| io_refused("reopen refs/heads", &error))?;
    let mut components = name.split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            dir.write_file(component, 0o644, format!("{oid}\n").as_bytes())?;
        } else {
            dir = dir.ensure_child(component, 0o755)?;
        }
    }
    Ok(())
}

/// Copy one top-level member of the materialized history tree into `scratch`,
/// bounded at [`kata_types::tree_artifact::MAX_MEMBER_BYTES`]. `Ok(false)` when
/// the member is absent; a symlink member is refused by
/// [`Dir::open_child_file`]'s `O_NOFOLLOW` (`ELOOP`), which is the honest answer
/// to "the artifact held a link where git wants a file".
fn copy_member(history: &Dir, scratch: &Dir, name: &'static str) -> KataResult<bool> {
    let cname = std::ffi::CString::new(name).expect("an ASCII literal");
    let file = match history.open_child_file(&cname) {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => {
            return Err(io_refused(
                &format!("open the history artifact's {name}"),
                &error,
            ));
        }
    };
    let mut bytes = Vec::new();
    file.take(kata_types::tree_artifact::MAX_MEMBER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_refused(&format!("read the history artifact's {name}"), &error))?;
    if bytes.len() as u64 > kata_types::tree_artifact::MAX_MEMBER_BYTES {
        return Err(refused(format!(
            "the history artifact's {name} member exceeds MAX_MEMBER_BYTES — the materializer's \
             own member bound applies to the copy, so the scratch repository never inherits a \
             member this node does not produce"
        )));
    }
    scratch.write_file(name, 0o644, &bytes)?;
    Ok(true)
}

/// The deepest directory the evidence read's admission walk descends to under
/// `git/` (the scratch dir itself is depth 0). git's own layout is at most
/// `refs/heads/<branch components>`; the bound exists so a guest-built chain of
/// directories cannot hold one descriptor per level open in the worker.
pub const SCRATCH_TREE_DEPTH: usize = 64;
/// The largest `HEAD`, `packed-refs` or file under `refs/` the evidence read
/// admits — the files gix reads WHOLE to resolve the scratch ref.
pub const SCRATCH_CONTROL_FILE_BYTES: u64 = 1 << 20;
/// The largest object the evidence read decodes: its DECLARED size, which gix
/// allocates before it inflates a byte, and — for a loose object in the scratch
/// store, which gix reads whole — its file's size.
pub const SCRATCH_OBJECT_BYTES: u64 = 16 << 20;

fn evidence_refused(reason: impl std::fmt::Display) -> KataError {
    KataError::Storage(format!("git_view evidence refused: {reason}"))
}

/// `error` and every `source()` beneath it — the walk's errors wrap the
/// bounded finder's refusal, and a refusal that does not reach the text is not
/// one an operator can act on.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// Admit the guest-written scratch dir for the host-side read: every entry,
/// walked descriptor-relative and never through a link, must be a directory or
/// a regular file.
///
/// # Refused set
///
/// * `git_view_evidence_entry_not_regular` — any entry under `git/` whose own
///   kind (`lstat`) is not directory or regular file: a symlink, a FIFO, a
///   socket, a character or block device;
/// * `git_view_evidence_commondir` — a top-level `commondir`, which would make
///   gix read the repository's refs and objects from the path it names;
/// * `git_view_evidence_pack` — any entry under `objects/pack/`: pack decoding
///   allocates from sizes the pack declares at every link of a delta chain, which
///   no header check bounds, so the guest's store is admitted loose-only;
/// * `git_view_evidence_file_too_large` — `HEAD`, `packed-refs` or a file under
///   `refs/` over [`SCRATCH_CONTROL_FILE_BYTES`];
/// * `git_view_evidence_too_deep` — a directory deeper than [`SCRATCH_TREE_DEPTH`];
/// * any listing, `stat` or open failure, naming its path.
fn admit_scratch_tree(dir: &Dir, relative: &str, depth: usize) -> KataResult<()> {
    let shown = |path: &str| format!("`git/{path}`");
    let names = dir
        .entries()
        .map_err(|error| evidence_refused(format!("list {}: {error}", shown(relative))))?;
    for name in names {
        let path = match relative {
            "" => String::from_utf8_lossy(name.to_bytes()).into_owned(),
            parent => format!("{parent}/{}", String::from_utf8_lossy(name.to_bytes())),
        };
        if relative == "objects/pack" {
            return Err(evidence_refused(format!(
                "git_view_evidence_pack: {} — the scratch store is read loose-only, because a \
                 pack declares the sizes its decoder allocates",
                shown(&path)
            )));
        }
        if path == "commondir" {
            return Err(evidence_refused(format!(
                "git_view_evidence_commondir: {} would point the read at another repository",
                shown(&path)
            )));
        }
        let stat = dir
            .stat_child(&name)
            .map_err(|error| evidence_refused(format!("stat {}: {error}", shown(&path))))?;
        match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
            rustix::fs::FileType::Directory => {
                if depth + 1 > SCRATCH_TREE_DEPTH {
                    return Err(evidence_refused(format!(
                        "git_view_evidence_too_deep: {} is nested past {SCRATCH_TREE_DEPTH} \
                         directories",
                        shown(&path)
                    )));
                }
                let child = dir
                    .open_child_dir(&name)
                    .map_err(|error| evidence_refused(format!("open {}: {error}", shown(&path))))?;
                admit_scratch_tree(&child, &path, depth + 1)?;
            }
            rustix::fs::FileType::RegularFile => {
                let control = path == "HEAD" || path == "packed-refs" || path.starts_with("refs/");
                let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
                if control && size > SCRATCH_CONTROL_FILE_BYTES {
                    return Err(evidence_refused(format!(
                        "git_view_evidence_file_too_large: {} holds {size} bytes, over the \
                         {SCRATCH_CONTROL_FILE_BYTES}-byte bound on a file read whole",
                        shown(&path)
                    )));
                }
            }
            kind => {
                return Err(evidence_refused(format!(
                    "git_view_evidence_entry_not_regular: {} is a {kind:?}; the read admits \
                     directories and regular files only, so it never follows a link out of the \
                     attempt root or opens what can block",
                    shown(&path)
                )));
            }
        }
    }
    Ok(())
}

/// The object reads of the evidence walk, each checked before gix decodes it:
/// a loose file of the id in the scratch store must be at most
/// [`SCRATCH_OBJECT_BYTES`] on disk (`git_view_evidence_file_too_large`), and
/// the object's declared size at most the same (`git_view_evidence_object_too_large`).
///
/// A commit the history's `shallow` file names is read WITHOUT its parents —
/// git's own reading of a depth-limited repository, whose boundary commits name
/// parents the history does not carry. Without it, hiding the base's ancestry
/// walks past the boundary into an object no store holds.
struct BoundedObjects<'a> {
    odb: &'a gix::OdbHandle,
    scratch_objects: &'a Dir,
    /// The history's shallow boundary, sorted.
    shallow: &'a [gix::ObjectId],
}

impl BoundedObjects<'_> {
    fn admit(&self, id: &gix::oid) -> KataResult<()> {
        let hex = id.to_hex().to_string();
        let (fan, rest) = hex.split_at(2);
        let fan = std::ffi::CString::new(fan).expect("hex has no NUL");
        let rest = std::ffi::CString::new(rest).expect("hex has no NUL");
        let loose = match self.scratch_objects.open_child_dir(&fan) {
            Ok(fan_dir) => match fan_dir.stat_child(&rest) {
                Ok(stat) => Some(u64::try_from(stat.st_size).unwrap_or(u64::MAX)),
                Err(rustix::io::Errno::NOENT) => None,
                Err(error) => {
                    return Err(evidence_refused(format!(
                        "stat loose object {hex}: {error}"
                    )));
                }
            },
            Err(rustix::io::Errno::NOENT) => None,
            Err(error) => {
                return Err(evidence_refused(format!(
                    "open loose fan-out of {hex}: {error}"
                )));
            }
        };
        if let Some(size) = loose.filter(|size| *size > SCRATCH_OBJECT_BYTES) {
            return Err(evidence_refused(format!(
                "git_view_evidence_file_too_large: loose object {hex} holds {size} bytes, over \
                 the {SCRATCH_OBJECT_BYTES}-byte bound on an object the walk reads"
            )));
        }
        match gix::objs::FindHeader::try_header(self.odb, id) {
            Ok(Some(header)) if header.size > SCRATCH_OBJECT_BYTES => {
                Err(evidence_refused(format!(
                    "git_view_evidence_object_too_large: object {hex} declares {} bytes, over the \
                     {SCRATCH_OBJECT_BYTES}-byte bound — refused before anything is allocated \
                     for it",
                    header.size
                )))
            }
            Ok(_) => Ok(()),
            Err(error) => Err(evidence_refused(format!(
                "the header of object {hex} could not be read: {}",
                error_chain(error.as_ref())
            ))),
        }
    }
}

impl gix::objs::Find for BoundedObjects<'_> {
    fn try_find<'b>(
        &self,
        id: &gix::oid,
        buffer: &'b mut Vec<u8>,
    ) -> Result<Option<gix::objs::Data<'b>>, gix::objs::find::Error> {
        self.admit(id).map_err(Box::new)?;
        if self.shallow.binary_search(&id.to_owned()).is_err() {
            return gix::objs::Find::try_find(self.odb, id, buffer);
        }
        let (kind, bytes) = match gix::objs::Find::try_find(self.odb, id, buffer)? {
            None => return Ok(None),
            Some(data) if data.kind == gix::object::Kind::Commit => {
                (data.kind, without_parents(data.data))
            }
            Some(data) => (data.kind, data.data.to_vec()),
        };
        buffer.clear();
        buffer.extend_from_slice(&bytes);
        Ok(Some(gix::objs::Data {
            kind,
            data: buffer.as_slice(),
        }))
    }
}

/// A commit object's bytes with every `parent` header line removed — the
/// header ends at the first empty line, and a continuation line (a signature's)
/// starts with a space, so only a real `parent` field matches.
fn without_parents(commit: &[u8]) -> Vec<u8> {
    let header_end = commit
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .map_or(commit.len(), |at| at + 1);
    let (header, rest) = commit.split_at(header_end);
    let mut out = Vec::with_capacity(commit.len());
    for line in header.split_inclusive(|byte| *byte == b'\n') {
        if !line.starts_with(b"parent ") {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(rest);
    out
}

/// The history's shallow boundary: the commit ids of `git-history/shallow`,
/// sorted, or none when the history is complete. The file is the HOST's — the
/// materialized artifact member, mounted read-only into the guest — never the
/// copy under the guest's `git/`. Bounded like every member copy, at
/// [`kata_types::tree_artifact::MAX_MEMBER_BYTES`].
fn history_shallow(attempt_root: &Path) -> KataResult<Vec<gix::ObjectId>> {
    let history_path = attempt_root.join(HISTORY_ROOT_NAME);
    let history = Dir::open(&history_path).map_err(|error| {
        evidence_refused(format!(
            "the history {} could not be opened: {error}",
            history_path.display()
        ))
    })?;
    let file = match history.open_child_file(c"shallow") {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(error) => {
            return Err(evidence_refused(format!(
                "open the history's shallow file: {error}"
            )));
        }
    };
    let mut bytes = Vec::new();
    file.take(kata_types::tree_artifact::MAX_MEMBER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| evidence_refused(format!("read the history's shallow file: {error}")))?;
    if bytes.len() as u64 > kata_types::tree_artifact::MAX_MEMBER_BYTES {
        return Err(evidence_refused(
            "the history's shallow file exceeds MAX_MEMBER_BYTES",
        ));
    }
    let mut shallow = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            gix::ObjectId::from_hex(line).map_err(|error| {
                evidence_refused(format!(
                    "the history's shallow file holds a line that is not an object id: {error}"
                ))
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    shallow.sort_unstable();
    Ok(shallow)
}

/// Read the scratch branch's own commits — the ones the agent created — as
/// bounded [`ScratchCommitReport`] rows, walked back from
/// `refs/heads/kata/<execution>` with the base commit's ancestry HIDDEN
/// (the walk's `hide` is git's `^base` semantics, so no commit of the shipped
/// history is ever reported as the agent's).
///
/// # Every byte under `git/` is the guest's
///
/// The READ happens on the host, after the container's teardown confirmed no
/// guest process remains — so nothing changes the tree between the checks
/// below and the reads they guard. But the guest had `/git` read-write, so the
/// tree is guest-chosen, and gix follows what a repository says: a link, a FIFO,
/// a `commondir`, an `include`, an alternates line, a `.git` beside the dir it
/// was handed. Before gix sees the dir:
///
/// 1. [`admit_scratch_tree`] walks it — see its refused set;
/// 2. `config` and `objects/info/alternates` are REPLACED with the bytes
///    [`materialize_git_view`] wrote ([`scratch_config`] of `view`;
///    [`ALTERNATES`]), so neither an include nor an alternates line the guest
///    wrote is ever read;
/// 3. gix opens the dir AS IS (never a `.git` inside it) with isolated
///    permissions (no system, global or environment configuration, no includes),
///    and with replace refs OFF on its object handle;
/// 4. the scratch ref is read by `try_id` — a symbolic one is refused
///    (`git_view_evidence_scratch_ref_symbolic`), never asked for an id it does
///    not have;
/// 5. every object the walk decodes goes through [`BoundedObjects`], which
///    also reads the history's shallow boundary commits without parents.
///
/// The alternates line is RELATIVE, so the replaced file names the history
/// mount on the host exactly as it did in the guest.
///
/// A scratch ref that no longer resolves (the agent deleted it) is not an
/// error — it is zero commits of evidence, the honest count of what the turn
/// left. Every other failure to read the scratch repository IS one: a corrupt
/// or refused scratch dir is evidence that could not be collected, not evidence
/// of none.
///
/// Every TEXT field of a report is scrubbed against `lifted` — the attempt's
/// lifted credential values — BEFORE the shared [`kata_types::redaction::elide`]
/// bound applies: a commit message can contain anything the vendor's process
/// held, and the report lands inside a durable blob where a token must never
/// be verbatim. Hex ids (`commit`, `parents`) are the object's own names and
/// cannot carry a secret, so they are not scrubbed.
///
/// # Errors
/// [`KataError::Storage`] naming the refusal, the gix failure or the read
/// failure; [`KataError::Validation`] for a malformed `view.base_commit`.
pub fn scratch_commits(
    attempt_root: &Path,
    execution: ulid::Ulid,
    attempt: ulid::Ulid,
    view: &CapsuleGitView,
    lifted: &kata_types::redaction::LiftedSecrets,
) -> KataResult<Vec<ScratchCommitReport>> {
    let base_commit = checked_base_commit(&view.base_commit)?;
    let scratch_path = attempt_root.join(SCRATCH_ROOT_NAME);
    let scratch = Dir::open(&scratch_path).map_err(|error| {
        evidence_refused(format!(
            "the scratch repository {} could not be opened: {error}",
            scratch_path.display()
        ))
    })?;
    admit_scratch_tree(&scratch, "", 0)?;
    scratch.replace_file(
        "config",
        0o644,
        scratch_config(view, &base_commit).as_bytes(),
    )?;
    let objects_dir = scratch
        .open_child_dir(c"objects")
        .map_err(|error| evidence_refused(format!("open the scratch object store: {error}")))?;
    objects_dir
        .ensure_child("info", 0o755)?
        .replace_file("alternates", 0o644, ALTERNATES)?;

    let mut repo = gix::open_opts(
        &scratch_path,
        gix::open::Options::isolated().open_path_as_is(true),
    )
    .map_err(|error| {
        KataError::Storage(format!(
            "git_view evidence: the scratch repository {} could not be opened: {error}",
            scratch_path.display()
        ))
    })?;
    // Set here, not left to gix's reading of an unset `core.useReplaceRefs`: a
    // guest `refs/replace/<id>` would otherwise substitute the object the walk
    // decodes — and the loose-file bound stats the ORIGINAL id's file.
    repo.objects.ignore_replacements = true;
    let scratch_ref = scratch_ref_name(execution);
    let reference = match repo.find_reference(scratch_ref.as_str()) {
        Ok(reference) => reference,
        Err(gix::reference::find::existing::Error::NotFound { .. }) => return Ok(Vec::new()),
        Err(error) => {
            return Err(KataError::Storage(format!(
                "git_view evidence: the scratch ref {scratch_ref} could not be resolved: {error}"
            )));
        }
    };
    // `try_id`, never `id`: `id` panics on a symbolic ref, and this ref is the
    // guest's to rewrite (`git symbolic-ref`).
    let Some(tip) = reference.try_id().map(gix::Id::detach) else {
        return Err(evidence_refused(format!(
            "git_view_evidence_scratch_ref_symbolic: {scratch_ref} names another ref, not a \
             commit — the evidence is the scratch branch's own commits, and a ref that only \
             points elsewhere has none"
        )));
    };
    let base = gix::ObjectId::from_hex(base_commit.as_bytes()).map_err(|error| {
        KataError::Storage(format!(
            "git_view evidence: the capsule's base commit `{base_commit}` does not parse as an \
             object id: {error}"
        ))
    })?;
    let shallow = history_shallow(attempt_root)?;
    let objects = BoundedObjects {
        odb: &repo.objects,
        scratch_objects: &objects_dir,
        shallow: &shallow,
    };
    let walk = gix::traverse::commit::Simple::new([tip], &objects)
        .hide([base])
        .map_err(|error| {
            KataError::Storage(format!(
                "git_view evidence: the scratch branch {scratch_ref} could not be walked: {}",
                error_chain(&error)
            ))
        })?;
    let mut commits = Vec::new();
    let mut buffer = Vec::new();
    // `take(MAX + 1)` bounds the WALK, not just the report: a scratch branch
    // holding thousands of agent commits is walked one past the bound and no
    // further.
    for info in walk.take(MAX_SCRATCH_COMMITS + 1) {
        let info = info.map_err(|error| {
            KataError::Storage(format!(
                "git_view evidence: the walk failed: {}",
                error_chain(&error)
            ))
        })?;
        if commits.len() == MAX_SCRATCH_COMMITS {
            break;
        }
        let unreadable = |reason: String| {
            KataError::Storage(format!(
                "git_view evidence: commit {} could not be read: {reason}",
                info.id
            ))
        };
        let data = gix::objs::Find::try_find(&objects, &info.id, &mut buffer)
            .map_err(|error| unreadable(error_chain(error.as_ref())))?
            .ok_or_else(|| unreadable("it is not in the store".to_owned()))?;
        if data.kind != gix::object::Kind::Commit {
            return Err(unreadable(format!("it is a {}", data.kind)));
        }
        let commit = gix::objs::CommitRef::from_bytes(data.data)
            .map_err(|error| unreadable(error.to_string()))?;
        let author = commit.author().map_err(|error| {
            KataError::Storage(format!(
                "git_view evidence: commit {}'s author: {error}",
                info.id
            ))
        })?;
        let committer = commit.committer().map_err(|error| {
            KataError::Storage(format!(
                "git_view evidence: commit {}'s committer: {error}",
                info.id
            ))
        })?;
        let message = String::from_utf8_lossy(commit.message).into_owned();
        let (subject, body) = split_message(&message);
        let parents: Vec<String> = info
            .parent_ids
            .iter()
            .take(SCRATCH_COMMIT_PARENT_LIMIT)
            .map(std::string::ToString::to_string)
            .collect();
        #[allow(clippy::cast_possible_truncation)]
        let parents_dropped =
            (info.parent_ids.len().saturating_sub(parents.len())).min(u32::MAX as usize) as u32;
        // Scrub BEFORE elide: a lifted token echoed into a commit field is
        // replaced while the whole string is still present — an elide first
        // could cut the token in half and leave the fragment unrecognised.
        // `bound` is that order as one call.
        let field = |text: &str| lifted.bound(text);
        commits.push(ScratchCommitReport {
            attempt_id: attempt,
            seq: commits.len() as u64,
            commit: info.id.to_string(),
            parents,
            parents_dropped,
            author_name: field(&author.name.to_str_lossy()),
            author_email: field(&author.email.to_str_lossy()),
            committer_name: field(&committer.name.to_str_lossy()),
            committer_email: field(&committer.email.to_str_lossy()),
            subject: field(&subject),
            body: field(&body),
        });
    }
    Ok(commits)
}

/// `subject`/`body` out of a raw commit message — the subject runs to the
/// first blank line (folding continuation lines as `git log %s` folds:
/// newlines become spaces), the body is everything after it.
fn split_message(message: &str) -> (String, String) {
    let message = message.trim_end_matches('\n');
    match message.find("\n\n") {
        Some(at) => {
            let subject = message[..at].replace('\n', " ");
            let body = message[at + 2..].to_owned();
            (subject, body)
        }
        None => (message.replace('\n', " "), String::new()),
    }
}
