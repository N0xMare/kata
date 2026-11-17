//! The main side of the git view: the HISTORY artifact an agent capsule's
//! disposable `/work` repository is materialized from — the objects reachable
//! from the execution workspace's committed base commit (within
//! `history_depth`) and from the frozen target's compare base down to their
//! merge base, packed.
//!
//! The artifact is a tree manifest over a git object store's innards:
//! `objects/pack/pack-<hash>.{pack,idx}` members (each at most
//! [`kata_types::tree_artifact::MAX_MEMBER_BYTES`], named by the pack's own
//! trailer digest exactly as `Bundle::write_to_directory` would name it), an
//! `index` member built from the base tree with zeroed stat data (git
//! refreshes it on the first `status`), and a `shallow` member when
//! `history_depth` truncated the walk — the boundary commit ids, one per line.
//! The worker mounts it read-only and the scratch gitdir reaches it through
//! `objects/info/alternates`. Every pack is written SELF-CONTAINED — the pack
//! index writer refuses ref-delta entries, so an entry whose delta base landed
//! in an earlier pack of this same artifact is re-read from the store and
//! re-emitted as a full object rather than recorded as a ref-delta.
//!
//! # What the walk ships — and what it can never ship
//!
//! `count::objects` with `ObjectExpansion::TreeContents` expands each selected
//! commit into its tree and every object beneath it — the reachable set of a
//! clone bounded to the base commit. The selected commits are the base's
//! ancestry within `history_depth`, plus the target's REVIEW RANGE whatever the
//! depth: every commit from the base and from the compare base down to their
//! merge base, and the merge base itself. Objects the host repository holds
//! that neither the base nor the frozen compare base reaches (unpushed
//! branches, stash, reflog garbage) are never counted: the walks start at those
//! two ids and descend, so the rest is absent by construction, not by
//! filtering.
//!
//! The view's branch ref comes off the frozen target too — trunk's name at the
//! base for a trunk target, a pull request's base branch at its compare base —
//! never off a trunk resolved now.
//!
//! # Refused set
//!
//! * `git_view_requires_git_backend` — the jj store has no git object store
//!   behind it, so there is no history to pack;
//! * `git_view_base_commit_absent` — the committed base is not a commit in the
//!   git store (a trunkless repository's empty-root base, or a store that
//!   lost it);
//! * `git_view_base_not_the_target` — the workspace's committed base is not
//!   the head the execution's target froze;
//! * `git_view_review_range_over_ceiling` — the artifact, with the target's
//!   review range included, is over `[git_view] history_bytes_ceiling` and the
//!   range reached commits the depth-bounded walk did not. It names that the
//!   delivered set exceeds what `history_depth` alone asked for, not that the
//!   range's own bytes are the larger part: an artifact the depth-bounded walk
//!   would also have put over the ceiling is named this too whenever the range
//!   added a commit;
//! * `git_view_identity_unavailable` — no inherited commit identity: the same
//!   refusal `create_workspace` runs at admission (`resolve_commit_identity`),
//!   mapped to the token the design names;
//! * `git_view_history_over_ceiling` — the artifact's member bytes total more
//!   than `[git_view] history_bytes_ceiling`;
//! * `git_view_member_too_large` — a single pack exceeds the tree-member bound
//!   [`MAX_MEMBER_BYTES`], which no split can repair (a pack is the member);
//! * `work_tree_base_unrepresentable` — via
//!   [`JjBackend::workspace_base_commit`], a `@` whose base is not one commit.
//!
//! The `index` member is built with gix's dot-git protections and without its
//! Windows-only checks. It refuses a component that spells `.git` in any ASCII
//! case (`.GIT`), with a code point HFS+ ignores (`.g\u{200c}it`), or as NTFS
//! reads it (`git~1`, or either followed by trailing dots, spaces or a `:`
//! stream), and a symlinked `.gitmodules` in HFS's and NTFS's spellings; any
//! other name Linux admits — `docs/a:b.md`, `?`, `*`, a trailing dot, `CON` — is
//! viewed. A base tree naming a dot-git component fails the index build
//! (`Internal`); one naming `.git` itself never gets here, because jj's
//! checkout refuses it when the workspace is created.
//!
//! IO failures of things the producer MUST read — the git store, a commit, an
//! object — are `Internal`/`Storage`, never a silently skipped member: a
//! skipped object would assemble a history that disagrees with the base commit
//! it claims to carry.

use std::collections::{BTreeMap, HashSet};
use std::io::Write as _;
use std::sync::atomic::AtomicBool;

use jj_lib::repo::Repo as _;
use kata_types::execution_contract::GitViewRef;
use kata_types::primitives::ObjectId;
use kata_types::target::ExecutionTarget;
use kata_types::tree_artifact::{
    CommittedBaseGitView, MAX_MEMBER_BYTES, TreeEntry, TreeEntryMode, TreeManifest, TreeNode,
    TreePath,
};
use kata_types::{KataError, KataResult};

use kata_effects_contract::{
    ExecutionWorkspaceHandle, GIT_VIEW_BASE_COMMIT_ABSENT, GIT_VIEW_BASE_NOT_THE_TARGET,
    GIT_VIEW_HISTORY_OVER_CEILING, GIT_VIEW_IDENTITY_UNAVAILABLE, GIT_VIEW_MEMBER_TOO_LARGE,
    GIT_VIEW_REQUIRES_GIT_BACKEND, GIT_VIEW_REVIEW_RANGE_OVER_CEILING,
};

use super::JjBackend;
use super::census::common_git_dir;

/// Objects per work chunk handed to the pack generator — the size gitoxide
/// itself uses for `pack create`.
const CHUNK_SIZE: usize = 200;

/// The emit form one output entry resolves to — either the entry's own
/// compressed payload (a base object, or an ofs-delta whose base is in the
/// SAME pack), or the re-read, re-deflated full object a delta becomes when
/// its base is not.
struct Emission {
    /// The pack entry header as written.
    header: gix_pack::data::entry::Header,
    /// The compressed payload that follows the header.
    compressed: Vec<u8>,
    /// The object's decompressed size — the header's size field.
    decompressed_size: u64,
}

/// One self-contained pack under assembly: its encoded bytes (header +
/// entries + trailer appended at flush) and each entry's stream position, so a
/// `DeltaRef` can be translated to the ofs-distance it encodes.
struct PackInProgress {
    /// `header::encode(V2, n)` followed by entry headers + payloads. The
    /// object count is patched at flush — entries stream in before the count
    /// is final.
    bytes: Vec<u8>,
    /// How many entries the pack holds so far.
    count: u32,
    /// `stream_index - first_stream_index` → pack offset of that entry's
    /// header, for entries IN THIS PACK ONLY.
    offsets: Vec<u64>,
    /// The global stream index of this pack's first entry: a `DeltaRef` whose
    /// `object_index` is below it names a base an earlier pack already holds.
    first_stream_index: usize,
}

impl PackInProgress {
    fn fresh() -> Self {
        Self {
            bytes: gix_pack::data::header::encode(gix_pack::data::Version::V2, 0).to_vec(),
            count: 0,
            offsets: Vec::new(),
            first_stream_index: 0,
        }
    }
}

impl JjBackend {
    /// Produce the execution's git-history artifact.
    ///
    /// Resolves the workspace's committed base commit ([`Self::workspace_base_commit`],
    /// the same read the `/work` head's conversion runs), walks the commits
    /// reachable from it newest-first through the git store the jj backend
    /// sits on, and streams `objects/pack/pack-*.{pack,idx}`, `index` and a
    /// possible `shallow` to `put_member`. Every member's bytes land in CAS as
    /// produced; the manifest is assembled and returned for the publisher to
    /// declare.
    ///
    /// # Errors
    ///
    /// The module-level refused set, each `KataError::Validation` under its
    /// named token; `Internal`/`Storage` on the store, commit and encode
    /// failures the producer cannot claim a refusal for.
    pub(super) fn committed_base_git_history(
        &self,
        handle: &ExecutionWorkspaceHandle,
        target: &ExecutionTarget,
        depth: Option<u32>,
        byte_ceiling: u64,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseGitView> {
        let (repo, _wc_commit, base_commit) = self.workspace_base_commit(handle)?;
        let base_hex = jj_lib::object_id::ObjectId::hex(base_commit.id());
        // The view shows the agent the commit admission froze, or nothing: a
        // workspace whose base is anything else was not created from this
        // target.
        if let Some(head) = target.head.commit()
            && head != base_hex
        {
            return Err(KataError::Validation(format!(
                "{GIT_VIEW_BASE_NOT_THE_TARGET}: the execution workspace's committed base is \
                 `{base_hex}`, and its target froze `{head}`"
            )));
        }

        let git_backend = jj_lib::git::get_git_backend(repo.store()).map_err(|err| {
            KataError::Validation(format!(
                "{GIT_VIEW_REQUIRES_GIT_BACKEND}: the jj backend behind this execution \
                 workspace is not a git store ({err}), so there is no object history to pack \
                 for the agent's /work git view"
            ))
        })?;
        let git_dir = common_git_dir(git_backend.git_repo_path());
        let repo_git = gix::open(&git_dir).map_err(|err| {
            KataError::Internal(format!(
                "git-view history could not open the git store {}: {err}",
                git_dir.display()
            ))
        })?;
        let object_hash = repo_git.object_hash();

        // The capsule's loose refs are written by the worker as text — check
        // the base resolves to a COMMIT in this store here, at admission,
        // rather than booting a view whose refs dangle.
        let base_oid = gix::hash::ObjectId::from_hex(base_hex.as_bytes()).map_err(|err| {
            KataError::Internal(format!(
                "git-view history: the jj base commit id `{base_hex}` is not a git object \
                 id: {err}"
            ))
        })?;
        let base_object = repo_git.find_object(base_oid).map_err(|err| {
            KataError::Validation(format!(
                "{GIT_VIEW_BASE_COMMIT_ABSENT}: the committed base `{base_hex}` is not an \
                 object the git store behind this workspace holds ({err}) — a trunkless \
                 repository's empty-root base is the jj root commit, which has no git object"
            ))
        })?;
        if base_object.kind != gix::objs::Kind::Commit {
            return Err(KataError::Validation(format!(
                "{GIT_VIEW_BASE_COMMIT_ABSENT}: the committed base `{base_hex}` resolves to a \
                 {} in the git store — a commit id is the only honest root for a git history",
                base_object.kind
            )));
        }
        drop(base_object);

        // The view's branch ref, off the frozen target: a PR's base branch at
        // the compare base, trunk's name at the head, or none.
        let branch = match (&target.pull_request, &target.compare, &target.branch) {
            (Some(pr), Some(compare), _) => Some(GitViewRef {
                name: smol_str::SmolStr::from(pr.base_ref.as_str()),
                commit: smol_str::SmolStr::from(compare.commit.as_str()),
            }),
            (None, _, Some(name)) => Some(GitViewRef {
                name: smol_str::SmolStr::from(name.as_str()),
                commit: smol_str::SmolStr::from(base_hex.as_str()),
            }),
            _ => None,
        };

        // The inherited identity the scratch repository's config carries — the
        // SAME `resolve_commit_identity` `create_workspace` runs at admission,
        // resolved per operation so an operator fixing their git config is not
        // stuck behind a cached answer.
        let identity = crate::identity::resolve_commit_identity(
            &crate::identity::observe_identity_at(self.repo_root()),
        )
        .map_err(|err| KataError::Validation(format!("{GIT_VIEW_IDENTITY_UNAVAILABLE}: {err}")))?;
        let identity = kata_types::execution_contract::GitIdentity {
            name: smol_str::SmolStr::from(identity.name.as_str()),
            email: smol_str::SmolStr::from(identity.email.as_str()),
        };

        // The commit set: newest-first from the base, truncated at `depth`.
        // `rev_walk` yields `Info`s carrying parent ids, so the shallow
        // boundary — commits inside the set whose parents are not — is
        // computed from the same pass rather than re-parsed.
        let mut commits: Vec<gix::hash::ObjectId> = Vec::new();
        let mut shallow: Vec<gix::hash::ObjectId> = Vec::new();
        let mut review_range_extended = false;
        {
            let limit = depth.map(|d| d as usize);
            let mut infos: Vec<(gix::hash::ObjectId, Vec<gix::hash::ObjectId>)> = Vec::new();
            for info in repo_git
                .rev_walk([base_oid])
                .sorting(gix::revision::walk::Sorting::ByCommitTime(
                    gix::traverse::commit::simple::CommitTimeOrder::NewestFirst,
                ))
                .all()
                .map_err(|err| {
                    KataError::Internal(format!(
                        "git-view history could not walk the commit ancestry of {base_hex}: \
                         {err}"
                    ))
                })?
            {
                let info = info.map_err(|err| {
                    KataError::Internal(format!(
                        "git-view history could not read a commit walking {base_hex}: {err}"
                    ))
                })?;
                infos.push((info.id, info.parent_ids.iter().copied().collect()));
                if limit.is_some_and(|n| infos.len() >= n) {
                    break;
                }
            }
            // The REVIEW RANGE rides whatever the depth: every commit from the
            // head and from the compare base down to their merge base, and the
            // merge base itself, so `git diff <merge-base>` and
            // `git log <base>..` answer inside the view.
            let mut included: HashSet<gix::hash::ObjectId> =
                infos.iter().map(|(id, _)| *id).collect();
            if let Some(compare) = &target.compare {
                let merge_base = git_oid(&compare.merge_base)?;
                let tips = [base_oid, git_oid(&compare.commit)?];
                for info in repo_git
                    .rev_walk(tips)
                    .with_hidden([merge_base])
                    .all()
                    .map_err(|err| {
                        KataError::Internal(format!(
                            "git-view history could not walk the review range down to \
                             {merge_base}: {err}"
                        ))
                    })?
                {
                    let info = info.map_err(|err| {
                        KataError::Internal(format!(
                            "git-view history could not read a review-range commit: {err}"
                        ))
                    })?;
                    if included.insert(info.id) {
                        review_range_extended = true;
                        infos.push((info.id, info.parent_ids.iter().copied().collect()));
                    }
                }
                if included.insert(merge_base) {
                    review_range_extended = true;
                    let commit = repo_git.find_commit(merge_base).map_err(|err| {
                        KataError::Internal(format!(
                            "git-view history could not read the merge base {merge_base}: {err}"
                        ))
                    })?;
                    infos.push((
                        merge_base,
                        commit.parent_ids().map(gix::Id::detach).collect(),
                    ));
                }
            }
            for (id, parents) in &infos {
                commits.push(*id);
                if parents.iter().any(|parent| !included.contains(parent)) {
                    shallow.push(*id);
                }
            }
        }

        // `iter_from_counts` resolves each entry's in-pack location through
        // `location_by_oid`, which the odb handle refuses unless it is pinned
        // to keep deleted packs mapped — clone handles inherit the mode.
        let mut odb = repo_git.objects.clone().into_inner();
        odb.prevent_pack_unload();

        // counts — every object the selected commits reach, expanded from each
        // commit's tree. `thread_limit: Some(1)` keeps ordering deterministic:
        // a re-driven admission (the crash window's recovery) produces the same
        // artifact, and a byte-stable pack keeps CAS dedup exact.
        let (counts, _count_outcome) =
            gix_pack::data::output::count::objects(
                odb.clone(),
                Box::new(commits.into_iter().map(|id| {
                    Ok::<gix::hash::ObjectId, Box<dyn std::error::Error + Send + Sync>>(id)
                })),
                &gix::features::progress::Discard,
                &AtomicBool::new(false),
                gix_pack::data::output::count::objects::Options {
                    thread_limit: Some(1),
                    chunk_size: CHUNK_SIZE,
                    input_object_expansion:
                        gix_pack::data::output::count::objects::ObjectExpansion::TreeContents,
                },
            )
            .map_err(|err| {
                KataError::Internal(format!("git-view history could not count objects: {err}"))
            })?;

        // entries → packs: stream the resolved entries in sequence order
        // (chunks can arrive out of order under the reduce; the BTreeMap
        // reorders and `next_seq` asserts contiguity), cutting a pack whenever
        // the next entry would exceed the member bound and the current pack
        // is non-empty.
        let ceiling = Ceiling {
            bytes: byte_ceiling,
            review_range_extended,
        };
        let trailer_len = object_hash.len_in_bytes() as u64;
        let mut members: Vec<TreeEntry> = Vec::new();
        let mut member_bytes_total: u64 = 0;
        let mut pack = PackInProgress::fresh();
        let mut stream_index: usize = 0;
        let mut buffered: BTreeMap<usize, Vec<gix_pack::data::output::Entry>> = BTreeMap::new();
        let mut next_seq: usize = 0;
        let iter = gix_pack::data::output::entry::iter_from_counts(
            counts,
            odb.clone(),
            Box::new(gix::features::progress::Discard),
            gix_pack::data::output::entry::iter_from_counts::Options {
                thread_limit: Some(1),
                mode: gix_pack::data::output::entry::iter_from_counts::Mode::PackCopyAndBaseObjects,
                allow_thin_pack: false,
                chunk_size: CHUNK_SIZE,
                version: gix_pack::data::Version::V2,
            },
        );
        for chunk in iter {
            let (seq, chunk_entries) = chunk.map_err(|err| {
                KataError::Internal(format!(
                    "git-view history could not resolve pack entries: {err}"
                ))
            })?;
            buffered.insert(seq, chunk_entries);
            while let Some(ready) = buffered.remove(&next_seq) {
                for entry in ready {
                    let emission = emit_entry(&odb, &entry, &pack)?;
                    let wire_size = emission.header.size(emission.decompressed_size) as u64
                        + emission.compressed.len() as u64;
                    if wire_size + 12 + trailer_len > MAX_MEMBER_BYTES {
                        return Err(KataError::Validation(format!(
                            "{GIT_VIEW_MEMBER_TOO_LARGE}: the git object {} encodes to \
                             {wire_size} bytes in a history pack — over the tree member bound \
                             {MAX_MEMBER_BYTES}, which no pack split can repair (a pack is the \
                             member)",
                            entry.id
                        )));
                    }
                    if pack.count > 0
                        && (pack.bytes.len() as u64 + wire_size + trailer_len) > MAX_MEMBER_BYTES
                    {
                        flush_pack(
                            &mut pack,
                            object_hash,
                            &mut members,
                            &mut member_bytes_total,
                            ceiling,
                            put_member,
                        )?;
                        pack.first_stream_index = stream_index;
                    }
                    let offset = pack.bytes.len() as u64;
                    emission
                        .header
                        .write_to(emission.decompressed_size, &mut pack.bytes)
                        .map_err(|err| {
                            KataError::Internal(format!(
                                "git-view history could not encode a pack entry header: {err}"
                            ))
                        })?;
                    pack.bytes.extend_from_slice(&emission.compressed);
                    pack.offsets.push(offset);
                    pack.count += 1;
                    stream_index += 1;
                }
                next_seq += 1;
            }
        }
        if !buffered.is_empty() {
            return Err(KataError::Internal(format!(
                "git-view history's pack stream ended with {} unordered chunks still buffered — \
                 a non-contiguous sequence is a resolve defect, not pack content",
                buffered.len()
            )));
        }
        if pack.count > 0 {
            flush_pack(
                &mut pack,
                object_hash,
                &mut members,
                &mut member_bytes_total,
                ceiling,
                put_member,
            )?;
        }

        // `index` — the base tree as a git index, zeroed stat so git refreshes
        // on the first status rather than trusting mtimes that were never real.
        let base_commit_obj = repo_git.find_commit(base_oid).map_err(|err| {
            KataError::Internal(format!(
                "git-view history could not re-read the base commit {base_hex}: {err}"
            ))
        })?;
        let base_tree_oid = base_commit_obj.tree_id().map_err(|err| {
            KataError::Internal(format!(
                "git-view history could not decode the base commit's tree id: {err}"
            ))
        })?;
        // The dot-git protections stay on — HFS's spellings of `.git` with an
        // ignorable code point (`.g\u{200c}it`), NTFS's short-name and stream
        // spellings (`git~1`, `.git::$INDEX_ALLOCATION`), each in any case, and
        // a symlinked `.gitmodules` — and gix's Windows-only checks are off:
        // kata targets Linux, where `:`, `?`, `*`, `<`, `>`, `|`, `"`, `\`, a
        // trailing dot or space and a device name (`CON`) are ordinary file
        // names a base tree may carry, and refusing them here voided the run as
        // `Internal`.
        let index_state = gix::index::State::from_tree(
            base_tree_oid.as_ref(),
            repo_git.objects.clone(),
            gix::validate::path::component::Options {
                protect_windows: false,
                protect_hfs: true,
                protect_ntfs: true,
            },
        )
        .map_err(|err| {
            KataError::Internal(format!(
                "git-view history could not build the index over the base tree: {err}"
            ))
        })?;
        // `State::write_to` emits the index body only — no trailing object-hash
        // signature — so a raw state write fails `git fsck`'s "index file
        // sha1 signature" check the moment a capsule touches it. Only
        // `File::write_to` appends the digest. The path is unused: nothing on
        // this path calls `File::write`, and `write_to` streams to `index_bytes`.
        let index_file = gix::index::File::from_state(index_state, std::path::PathBuf::new());
        let mut index_bytes = Vec::new();
        index_file
            .write_to(&mut index_bytes, gix::index::write::Options::default())
            .map_err(|err| {
                KataError::Internal(format!(
                    "git-view history could not encode the index member: {err}"
                ))
            })?;
        add_member(
            &mut members,
            &mut member_bytes_total,
            ceiling,
            "index",
            &index_bytes,
            put_member,
        )?;

        if !shallow.is_empty() {
            let mut shallow_bytes = String::new();
            for id in &shallow {
                shallow_bytes.push_str(&id.to_hex().to_string());
                shallow_bytes.push('\n');
            }
            add_member(
                &mut members,
                &mut member_bytes_total,
                ceiling,
                "shallow",
                shallow_bytes.as_bytes(),
                put_member,
            )?;
        }

        let manifest = TreeManifest::new(members)?;
        let manifest_bytes = manifest.manifest_bytes()?;
        Ok(CommittedBaseGitView {
            base_commit: base_hex,
            branch,
            identity,
            manifest,
            manifest_bytes,
        })
    }
}

/// How `entry` lands in the pack under assembly: verbatim as an ofs-delta when
/// its base sits in the SAME pack, else re-emitted as the full object — the
/// artifact's packs are self-contained because the pack index writer refuses
/// ref-deltas, and a delta whose base lived in another member would be one.
fn emit_entry(
    odb: &gix::odb::Handle,
    entry: &gix_pack::data::output::Entry,
    pack: &PackInProgress,
) -> KataResult<Emission> {
    use gix_pack::Find as _;
    match entry.kind {
        gix_pack::data::output::entry::Kind::Base(kind) => Ok(Emission {
            header: base_header(kind),
            compressed: entry.compressed_data.clone(),
            decompressed_size: entry.decompressed_size as u64,
        }),
        gix_pack::data::output::entry::Kind::DeltaRef { object_index }
            if object_index >= pack.first_stream_index =>
        {
            let base_offset = pack.offsets[object_index - pack.first_stream_index];
            Ok(Emission {
                header: gix_pack::data::entry::Header::OfsDelta {
                    base_distance: (pack.bytes.len() as u64) - base_offset,
                },
                compressed: entry.compressed_data.clone(),
                decompressed_size: entry.decompressed_size as u64,
            })
        }
        _ => {
            // The base is in an earlier pack of this artifact — or the stream
            // produced a thin-pack spelling (`DeltaOid`) `allow_thin_pack =
            // false` should have excluded. Either way the pack records the
            // full object, re-read and re-deflated from the store.
            let mut buffer = Vec::new();
            let object = odb
                .try_find(&entry.id, &mut buffer)
                .map_err(|err| {
                    KataError::Internal(format!(
                        "git-view history could not re-read object {} for a pack-boundary \
                         re-emission: {err}",
                        entry.id
                    ))
                })?
                .ok_or_else(|| {
                    KataError::Internal(format!(
                        "git-view history: object {} named by the pack stream is absent from \
                         the store it was read from",
                        entry.id
                    ))
                })?
                .0;
            let mut compressed = gix::features::zlib::stream::deflate::Write::new(Vec::new());
            std::io::copy(&mut &*object.data, &mut compressed).map_err(|err| {
                KataError::Internal(format!(
                    "git-view history could not re-compress object {}: {err}",
                    entry.id
                ))
            })?;
            std::io::Write::flush(&mut compressed).map_err(|err| {
                KataError::Internal(format!(
                    "git-view history could not finish re-compressing object {}: {err}",
                    entry.id
                ))
            })?;
            let compressed = compressed.into_inner();
            Ok(Emission {
                header: base_header(object.kind),
                compressed,
                decompressed_size: object.data.len() as u64,
            })
        }
    }
}

/// The byte-range resolver `write_data_iter_to_stream` calls to re-read an
/// entry's bytes out of the pack being indexed — a named fn so the
/// `for<'r> Fn(EntryRange, &'r R) -> Option<&'r [u8]>` bound is met. The bound
/// pins `&Vec<u8>`: `R` is the owned pack bytes the factory clones.
#[allow(clippy::ptr_arg)]
fn resolve_entry_range(range: gix_pack::data::EntryRange, bytes: &Vec<u8>) -> Option<&[u8]> {
    let start = usize::try_from(range.start).ok()?;
    let end = usize::try_from(range.end).ok()?;
    bytes.get(start..end)
}

/// The base-object header variant for a git object kind.
fn base_header(kind: gix::objs::Kind) -> gix_pack::data::entry::Header {
    match kind {
        gix::objs::Kind::Tree => gix_pack::data::entry::Header::Tree,
        gix::objs::Kind::Blob => gix_pack::data::entry::Header::Blob,
        gix::objs::Kind::Commit => gix_pack::data::entry::Header::Commit,
        gix::objs::Kind::Tag => gix_pack::data::entry::Header::Tag,
    }
}

/// Finish a pack: patch the object count into the header, append the trailer
/// digest, produce the `.idx` by re-parsing the written bytes — the same
/// `streaming-input` + index-writer path `Bundle::write_to_directory` uses —
/// and publish `pack-<digest>.pack` / `pack-<digest>.idx` named by that
/// digest, the git convention. `member_bytes_total` carries the artifact-wide
/// running total the ceiling refusal reads.
fn flush_pack(
    pack: &mut PackInProgress,
    object_hash: gix::hash::Kind,
    members: &mut Vec<TreeEntry>,
    member_bytes_total: &mut u64,
    ceiling: Ceiling,
    put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
) -> KataResult<()> {
    pack.bytes[8..12].copy_from_slice(&pack.count.to_be_bytes());
    let mut hasher = gix::hash::hasher(object_hash);
    hasher.update(&pack.bytes);
    let trailer = hasher.try_finalize().map_err(|err| {
        KataError::Internal(format!(
            "git-view history could not digest a pack trailer: {err}"
        ))
    })?;
    pack.bytes.write_all(trailer.as_bytes()).map_err(|err| {
        KataError::Internal(format!(
            "git-view history could not write a pack trailer: {err}"
        ))
    })?;

    let pack_bytes = std::sync::Arc::new(std::mem::take(&mut pack.bytes));
    let mut entries_iter = gix_pack::data::input::BytesToEntriesIter::new_from_header(
        std::io::BufReader::new(std::io::Cursor::new(pack_bytes.as_slice())),
        gix_pack::data::input::Mode::Verify,
        gix_pack::data::input::EntryDataMode::Crc32,
        object_hash,
    )
    .map_err(|err| {
        KataError::Internal(format!(
            "git-view history produced a pack its own reader cannot re-parse: {err}"
        ))
    })?;
    let mut index_bytes = Vec::new();
    let outcome = gix_pack::index::File::write_data_iter_to_stream(
        gix_pack::index::Version::default(),
        {
            let pack_bytes = std::sync::Arc::clone(&pack_bytes);
            move || Ok((resolve_entry_range, (*pack_bytes).clone()))
        },
        &mut entries_iter,
        Some(1),
        &mut gix::features::progress::Discard,
        &mut index_bytes,
        &AtomicBool::new(false),
        object_hash,
        gix_pack::data::Version::V2,
    )
    .map_err(|err| {
        KataError::Internal(format!(
            "git-view history could not write the pack index: {err}"
        ))
    })?;
    drop(entries_iter);

    let name = format!("objects/pack/pack-{}", outcome.data_hash.to_hex());
    add_member(
        members,
        member_bytes_total,
        ceiling,
        &format!("{name}.idx"),
        &index_bytes,
        put_member,
    )?;
    add_member(
        members,
        member_bytes_total,
        ceiling,
        &format!("{name}.pack"),
        pack_bytes.as_slice(),
        put_member,
    )?;
    *pack = PackInProgress::fresh();
    Ok(())
}

/// The artifact's byte ceiling, and whether the target's review range added
/// commits the depth-bounded walk did not reach — which names the refusal.
#[derive(Clone, Copy)]
struct Ceiling {
    bytes: u64,
    review_range_extended: bool,
}

/// A 40-hex commit id off the frozen target, as a gix object id.
fn git_oid(hex: &str) -> KataResult<gix::hash::ObjectId> {
    gix::hash::ObjectId::from_hex(hex.as_bytes()).map_err(|err| {
        KataError::Internal(format!(
            "git-view history: the target's commit id `{hex}` is not a git object id: {err}"
        ))
    })
}

/// Append one member: charge its bytes against the ceiling (the refusal names
/// both knobs so the `history_depth` alternative sits beside the byte bound
/// the operator hit), publish them, and register the manifest entry.
fn add_member(
    members: &mut Vec<TreeEntry>,
    member_bytes_total: &mut u64,
    ceiling: Ceiling,
    path: &str,
    bytes: &[u8],
    put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
) -> KataResult<()> {
    *member_bytes_total += bytes.len() as u64;
    let byte_ceiling = ceiling.bytes;
    if *member_bytes_total > byte_ceiling && ceiling.review_range_extended {
        return Err(KataError::Validation(format!(
            "{GIT_VIEW_REVIEW_RANGE_OVER_CEILING}: the git history artifact totals \
             {member_bytes_total} member bytes with the target's review range included, over \
             this node's `[git_view] history_bytes_ceiling` of {byte_ceiling}. The review range \
             reached commits `history_depth` did not, and it is shipped whatever the depth says, \
             so the artifact is refused rather than truncated. Raise the ceiling; lowering \
             `history_depth` helps only when the depth-bounded history is the larger part",
        )));
    }
    if *member_bytes_total > byte_ceiling {
        return Err(KataError::Validation(format!(
            "{GIT_VIEW_HISTORY_OVER_CEILING}: the git history artifact totals \
             {member_bytes_total} member bytes, over this node's `[git_view] \
             history_bytes_ceiling` of {byte_ceiling}. Raise the ceiling, or bound the \
             walk with `[git_view] history_depth` — the artifact is produced once at \
             admission, never truncated silently",
        )));
    }
    let object = put_member(bytes)?;
    members.push(TreeEntry {
        path: TreePath::new(path.to_owned()).map_err(|err| {
            KataError::Internal(format!(
                "git-view history produced member path {path:?} the manifest refuses: {err}"
            ))
        })?,
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object,
            size_bytes: bytes.len() as u64,
        },
    });
    Ok(())
}
