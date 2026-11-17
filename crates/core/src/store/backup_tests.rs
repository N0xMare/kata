use super::*;
use crate::InFlightLedger;
use std::sync::Arc;
use ulid::Ulid;

/// The capture's refusal and the restore's clearing must be the SAME set.
///
/// **Invariant.** A database the capture will not carry is a database the
/// restore will not leave behind, and vice versa.
///
/// **Failure mode.** They are two functions. If the capture refuses a name
/// the restore does not clear, a restore into a live data directory leaves a
/// stale plane beside an authority rolled back underneath it — the dangling
/// state `clear_rebuildable_databases`' call site enumerates. If the restore
/// clears a name the capture DOES carry, the artifact's own copy is deleted
/// after being placed, which is data loss dressed as tidying.
///
/// **Enforcement point.** Both read [`AssetAuthority::Rebuildable`] off the
/// same map, one by [`classify_data_dir_entry`] and one by an iterator over
/// [`DURABLE_ASSETS`]. This asserts the two derivations agree over the whole
/// map rather than over the one name that exists today.
///
/// **What it REFUSES vs. what it CLAIMS.** It refuses any `<data_dir>`
/// `*.db` name on which the two disagree. It claims nothing about non-`.db`
/// rows or about `AssetLocation::DataDirPrefix` families: no `Rebuildable`
/// row has either shape, and a future one would have to re-derive both sides
/// anyway. The narrower gap, stated: `artifact_carries_database` folds
/// `-wal`/`-shm`/`-journal` sidecars through `classify_data_dir_entry` while
/// the clearing spells the three suffixes out, so a fourth SQLite sidecar
/// suffix would be refused by discovery (it is not a `*.db` name, so it never
/// reaches discovery at all) and NOT cleared. Nothing produces one.
#[test]
fn the_capture_and_the_restore_refuse_the_same_rebuildable_set() {
    let cleared: BTreeSet<&str> = rebuildable_data_dir_databases().collect();
    assert!(
        !cleared.is_empty(),
        "NON-VACUITY: the map must still hold a rebuildable database, or neither half of \
         this invariant is being exercised anywhere"
    );
    for name in &cleared {
        assert!(
            !artifact_carries_database(name),
            "{name} is cleared from a restore target but the capture still carries it: a \
             restore would place the artifact's copy and then delete it"
        );
    }

    let refused: BTreeSet<&str> = DURABLE_ASSETS
        .iter()
        .filter_map(|asset| match asset.location {
            AssetLocation::DataDirFile(name)
                if Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
                    && !artifact_carries_database(name) =>
            {
                Some(name)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        refused, cleared,
        "every `*.db` name the capture refuses must be one the restore clears, and no other"
    );
}

/// Every `rustix` open this module issues binds its FINAL component, with
/// exactly one carve-out that is named here rather than trusted.
///
/// **Invariant.** A path this module opens under a descriptor it proved
/// resolves to the object AT that name, never to whatever a symlink there
/// points at. `O_NOFOLLOW` is the only thing that establishes it.
///
/// **Failure mode.** The flag is per-call-site and hand-written eight times.
/// It silently went missing from `ProvenDir::open_source_file` — the one
/// site every artifact READ goes through — and nothing saw it: the
/// post-open `is_file()` check reports the TARGET of a followed link, so it
/// passes; the module's own FILES table credited the position with
/// `O_NOFOLLOW` in six rows; and the site's `Errno::LOOP` arm, unreachable
/// without the flag, read as proof the flag was there. The consequence was
/// operator-facing: `preflight_restore_artifact` returned `Ok` on an
/// artifact whose sole `cas` member was a link to a file outside it.
///
/// **Enforcement point.** Here, over this module's own source text, so a
/// site written TOMORROW is covered without anyone remembering to extend a
/// list. Prefer this to the rule it replaces: "every `ProvenDir` opener
/// carries `O_NOFOLLOW`" was written down in three places and still lost.
///
/// **What it REFUSES vs. what it CLAIMS.** It refuses a `rustix` `openat`/
/// `open` call, on a non-comment line of THIS file, whose argument text
/// before the mode argument does not contain `OFlags::NOFOLLOW`, unless the
/// enclosing function is in `RESOLVING_OPENS`. It does NOT cover: opens
/// written as `File::open`/`OpenOptions` or `std::fs::*` (those carry no
/// such flag at all and are owned by the module's DECLARED LIMITS section,
/// which names five surviving `lstat`-then-`open` positions); the
/// `#[cfg(not(unix))]` arms, which reach the same refusal by a separate
/// hand-written `lstat`; `rustix` opens in any OTHER module; and a site that
/// carries the flag and then re-resolves the same path by name. It is also
/// fail-CLOSED on a flags expression built indirectly (a constant or a
/// variable): the text would not contain the flag and the site would be
/// reported, which is a false positive, not a silent pass.
#[test]
fn every_proven_dir_openat_carries_o_nofollow() {
    /// The one position that must RESOLVE its final component: the artifact
    /// directory the OPERATOR typed. `DirectoryState` states why the
    /// carve-out exists and why it stops at the first component this module
    /// chose.
    const RESOLVING_OPENS: &[&str] = &["open_operator_root"];
    // Assembled at runtime so this test's own source does not match the
    // scan it performs.
    let stem = concat!("rustix", "::fs::open");
    let mode_arg = concat!("rustix", "::fs::Mode::");
    let source: &str = include_str!("backup.rs");

    let mut sites: Vec<(&str, bool)> = Vec::new();
    let mut offset = 0_usize;
    for line in source.lines() {
        // `lines()` strips the terminator; this file is LF, and an overshoot
        // past the last line is never read. The offset is TRACKED rather
        // than recovered with `source.find(line)`, because the matched lines
        // are not distinct: the eight sites are only THREE distinct strings
        // and one of them repeats four times, so a search would attribute
        // all four to the first and the scan would check one site four
        // times while reporting eight.
        let at = offset;
        offset += line.len() + 1;
        if line.trim_start().starts_with("//") {
            continue;
        }
        if !(line.contains(&format!("{stem}(")) || line.contains(&format!("{stem}at("))) {
            continue;
        }
        let owner = {
            let head = &source[..at];
            let start = head
                .rfind("\n    fn ")
                .expect("every rustix open in this module is inside an indented method")
                + "\n    fn ".len();
            let end = start
                + source[start..]
                    .find(['(', '<', ' ', '\n'])
                    .expect("a method name is followed by its parameter list");
            &source[start..end]
        };
        let tail = &source[at..];
        let flags_end = tail
            .find(mode_arg)
            .expect("every rustix open in this module passes a literal mode argument");
        sites.push((owner, tail[..flags_end].contains("OFlags::NOFOLLOW")));
    }

    // The scan selecting NOTHING would read as a pass, which is the trap
    // this repo names by name for test filters. Eight sites at the time of
    // writing; the bound is a floor, not a pin, so adding one is not a
    // failure and deleting the scanner's grip is.
    assert!(
        sites.len() >= 8,
        "the scan found {} open sites in this module, which means it stopped matching the \
         source rather than that the opens went away",
        sites.len()
    );
    let unbound: Vec<&str> = sites
        .iter()
        .filter(|(owner, nofollow)| !nofollow && !RESOLVING_OPENS.contains(owner))
        .map(|(owner, _)| *owner)
        .collect();
    assert!(
        unbound.is_empty(),
        "these opens do not bind their final component and are not declared resolving: {:?}. \
         Add `OFlags::NOFOLLOW`, or add the function to RESOLVING_OPENS with the argument for \
         why an operator-named prefix reaches it",
        unbound
    );
    for declared in RESOLVING_OPENS {
        assert!(
            sites.iter().any(|(owner, _)| owner == declared),
            "`{declared}` is declared as a resolving open and the scan did not find one in \
             it; a stale carve-out is how the next dropped flag gets excused"
        );
    }
}

/// The manifest's `config_included` boolean translates to a name the
/// durable-asset map actually carries.
///
/// [`BUNDLED_CONFIG_ASSET_NAME`] is a string constant standing in for a map
/// key, which is the shape that rots silently: if the map ever re-keys the
/// node config, [`manifest_completeness`] would go on reporting a bundled
/// config as MISSING and nothing would say why.
#[test]
fn the_bundled_config_name_resolves_to_an_authoritative_map_row() {
    let row = crate::durable_assets::DURABLE_ASSETS
        .iter()
        .find(|asset| asset.location.name() == BUNDLED_CONFIG_ASSET_NAME)
        .expect("the bundled node config must have a durable-asset map row");
    assert!(
        row.authority.is_authoritative(),
        "the node config is what a restored main is configured BY; if the map stops calling \
         it authoritative, omitting it stops being reportable, and it was {:?}",
        row.authority
    );
}

/// The structural inventory adapter cannot prove recoverability from admitted
/// database names, tree roots and the bundled-config flag alone. This v2 witness
/// maximizes those three inputs and independently pins the five missing groups.
/// It does not test the separate v4 recovery-treatment/verifier path.
///
/// Coverage is monotone in this captured set: adding a name only removes a
/// missing row. The final control constructs an inadmissible raw struct value
/// that does reach every row, distinguishing admission rules from the Rust type.
/// No assertion is removed: a widened structural channel still changes the
/// exact missing-group assertion. V3 verified recovery has its own positive and
/// refusal tests; this test makes no module-wide impossibility claim.
#[test]
fn structural_inventory_alone_cannot_earn_recoverable() {
    // CHANNEL 1 — the most generous name per map row that
    // `validate_database_names` admits and that resolves back to that row.
    // A `DataDirPrefix` family is named by any member file, so the witness
    // is `<prefix>.db` rather than the bare prefix.
    let mut databases: Vec<String> = DURABLE_ASSETS
        .iter()
        .map(|asset| match asset.location {
            AssetLocation::DataDirPrefix(prefix) => format!("{prefix}.db"),
            other => other.name().to_string(),
        })
        .filter(|candidate| validate_database_names(std::slice::from_ref(candidate)).is_ok())
        .filter(|candidate| {
            DURABLE_ASSETS
                .iter()
                .any(|asset| asset.location.name() == candidate.as_str())
                || classify_data_dir_entry(candidate).is_some()
        })
        .collect();
    databases.sort();
    databases.dedup();

    // CHANNEL 2 — every tree name `validate_tree_records` will accept, with
    // the matching evidence record, because a claim without one is refused.
    let mut trees: Vec<CapturedTree> = capturable_tree_assets()
        .map(|asset| CapturedTree {
            name: asset.location.name().to_string(),
            root: asset.location.root(),
            tier: durability_tier(asset.authority),
            entry_count: 0,
            total_byte_len: 0,
            entry_digest: Some(tree_entry_digest(&[])),
            entries: Vec::new(),
        })
        .collect();
    trees.sort_by(|left, right| left.name.cmp(&right.name));
    let tree_roots: Vec<String> = trees.iter().map(|tree| tree.name.clone()).collect();

    // CHANNEL 3 is the boolean, set below.
    //
    // The `assets` array is NOT a channel — `manifest_completeness` never
    // reads it — but a v2 manifest that lists a database and records no
    // durability entry for it is REFUSED by `validate_asset_records`, so a
    // manifest without one is not a manifest `read_manifest` will parse.
    // This array is what makes the claim below about READABLE manifests
    // rather than about constructible values; see the `expect` further down
    // for the refusal it earned when it was `Vec::new()`.
    //
    // The tier is `derived_tier` FLOORED AT `BestEffort`, and the floor is
    // the second thing this array taught. `validate_asset_records` refuses
    // an `Excluded` record by name — an excluded asset is not captured at
    // all — while `refuse_weakened_tier` accepts any tier at or above the
    // derivation. The map derives `Excluded` for the Transient rows a `*.db`
    // witness can reach (`.main-identity-.db` resolves to the
    // `.main-identity-` prefix row), so recording the derivation verbatim
    // produced a second unreadable manifest. Tier does not affect COVERAGE,
    // which is what this test is maximizing, so the weakest readable tier is
    // the honest choice.
    let assets: Vec<CapturedAsset> = databases
        .iter()
        .cloned()
        .chain(std::iter::once(CONFIG_COPY_NAME.to_string()))
        .map(|name| {
            let tier = derived_tier(&name).at_least(DurabilityTier::BestEffort);
            CapturedAsset {
                digest: (tier == DurabilityTier::Durable).then(|| "0".repeat(64)),
                name,
                tier,
                byte_len: 0,
            }
        })
        .collect();
    let manifest = BackupManifest {
        version: MANIFEST_VERSION,
        created_at_ms: 0,
        databases,
        config_included: true,
        artifact_id: Some(Ulid::new()),
        assets,
        capture_order: None,
        tree_roots,
        trees,
        producer: producer_identity().expect("this process can name its own executable"),
        recovery_assets: None,
        source_directory_id: None,
    };

    // READABLE, not merely constructible: the THREE admission rules
    // `read_manifest` runs before `manifest_completeness` can ever be called
    // on a manifest all accept this one, so the bound is over manifests that
    // can actually exist.
    //
    // This said "both admission rules" and called two of them.
    // `validate_asset_records` is the third, `read_manifest` runs it, and it
    // REFUSED the maximal manifest as written — `manifest version 2 lists
    // database ".main-identity-.db" and records no durability entry for it`
    // — so the test asserting a bound over readable manifests was built on a
    // manifest no reader accepts. Calling `read_manifest`'s own sequence
    // rather than a remembered subset of it is what stops that recurring.
    validate_database_names(&manifest.databases)
        .expect("the maximal database list must be one this module will read");
    validate_asset_records(&manifest)
        .expect("the maximal manifest must carry the durability records a v2 reader demands");
    validate_tree_records(&manifest)
        .expect("the maximal tree claim must be one this module will read");

    let verdict = manifest_completeness(&manifest);
    assert!(
        verdict.unclassified.is_empty(),
        "every witness must resolve to a map row, or this set is not the maximal COVERING one: \
         {:?}",
        verdict.unclassified
    );
    // Spelled ONCE, as a literal, and used twice: here as the bound, and
    // below as the only difference between the maximal READABLE manifest and
    // the VALUE that clears it. That reuse is what makes the counter-example
    // falsifiable — see the comment on it.
    let unclaimable = [
        "main-identity.json",
        "local-worker.secret",
        "subordinate-worker:idempotency.db",
        "subordinate-worker:credential_path",
        "vcs.jj_repo",
    ];
    assert_eq!(
        verdict.missing_authoritative,
        unclaimable.to_vec(),
        "these are the authoritative rows the admitted STRUCTURAL inventory cannot claim; \
         the shape of the three channels rather than the shape of the capture. A row leaving \
         this list means a channel widened — say which, and say what now reaches \
         `Recoverable`"
    );
    // THE CLASS IS NOT ASSERTED HERE EITHER, and this is the last round that
    // question gets asked.
    //
    // The line was `assert_eq!(verdict.class, DataSnapshot, …)` with a
    // comment claiming that widening a channel would red it and that this
    // was "the whole tripwire". It is not a tripwire at all: `class` is
    // DERIVED by `assess_backup_class` as `missing.is_empty() &&
    // unclassified.is_empty()`, and the two assertions above already pin
    // `unclassified` empty and `missing_authoritative` to a FIVE-element list.
    // A non-empty `missing` forces `DataSnapshot`, so the class line is
    // strictly implied by its predecessors and cannot red under any input
    // that reaches it — a channel wide enough to change the class reds the
    // `missing_authoritative` assertion first, by name, saying which row
    // moved.
    //
    // That is the third variant of this one line (`assert_ne!(…,
    // Recoverable)`, then `assert_eq!(…, DataSnapshot)`, then this comment),
    // and each was recorded as load-bearing. The falsifiable statement of
    // the bound is the five-name list above; the class is its arithmetic.
    // `assess_backup_class`'s own `Recoverable` branch is exercised by
    // `the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it`,
    // over a raw asset set, which is the only object that can reach it.

    // THE COUNTER-EXAMPLE, and the reason this test is named for what
    // `read_manifest` will READ rather than for `BackupManifest` values.
    //
    // Every prose statement of this bound said "for any manifest, honest or
    // forged". That is FALSE for a `BackupManifest` VALUE: the struct's
    // fields are `pub`, it is not `#[non_exhaustive]`, and nothing in the
    // type stops a caller writing the authoritative LOCATION NAMES straight
    // into `databases`. Doing so earns `Recoverable` with an empty missing
    // list, below, on this binary, today.
    //
    // That is not a hole in the bound — it is the bound's SUBJECT. The three
    // channels are narrow because `validate_database_names`,
    // `validate_asset_records` and `validate_tree_records` hold them so, and
    // those run inside `read_manifest`. A value assembled in-process has
    // passed none of them and is not an artifact; every production caller of
    // `manifest_completeness` is handed a manifest `read_manifest` produced.
    // The sentence has to say which object it covers, and this asserts the
    // difference rather than trusting it.
    //
    // # The forged set is the MAXIMAL one plus the five literals, and that is
    // what makes this falsifiable
    //
    // It was `DURABLE_ASSETS.iter().filter(is_authoritative).map(|asset|
    // asset.location.name())` — GENERATED by the same function
    // `manifest_completeness` RESOLVES by, so the missing list was empty for
    // every possible content of `DURABLE_ASSETS` and the assertion could not
    // red. That is the same vacuity the three retractions above are about,
    // written thirty lines under a comment declaring the question closed.
    //
    // Built this way it reds for a real change: the maximal manifest's
    // `databases` come from the CHANNEL construction at the top of this test,
    // and the five names come from the literal `unclaimable` list the bound
    // above is stated in. A new authoritative row no channel admits and no
    // literal names lands in `missing_authoritative` here and reds THIS line
    // — after reddening the bound above, which names it.
    let mut forged_databases = manifest.databases.clone();
    forged_databases.extend(unclaimable.iter().map(|name| (*name).to_string()));
    let forged = BackupManifest {
        databases: forged_databases,
        ..manifest.clone()
    };
    assert_eq!(
        manifest_completeness(&forged).class,
        crate::durable_assets::BackupClass::Recoverable,
        "a hand-built VALUE reaches every authoritative row and EARNS the class no readable \
         manifest can. If this stops being reachable, the three admission rules are no longer \
         what bounds `manifest_completeness` — find what does and restate the bound over it"
    );
    // The two objects differ in exactly one respect, and this is it.
    validate_database_names(&forged.databases).expect_err(
        "and `read_manifest` refuses it at the FIRST admission rule, which is why the same \
         names cannot reach the assessment through an artifact",
    );
}

/// [`MAX_TREE_COUNT`] is the map's own count, not a number beside it.
#[test]
fn the_tree_count_bound_matches_the_map() {
    let rows = crate::durable_assets::DURABLE_ASSETS
        .iter()
        .filter(|asset| matches!(asset.capture, CaptureRule::Tree { .. }))
        .count();
    assert_eq!(
        MAX_TREE_COUNT, rows,
        "`MAX_TREE_COUNT` bounds how many tree records a manifest may carry, and \
         `restorable_tree_asset` refuses any name that is not a `CaptureRule::Tree` row — so \
         a bound above the row count admits records that can only be refused, and one below \
         it refuses records the map licenses"
    );
}

/// The manifest bound ADMITS a maximal tree manifest, measured against real
/// serialized bytes.
///
/// This is the check that stops [`MAX_TREE_ENTRIES`] and
/// [`MAX_MANIFEST_BYTES`] drifting apart into the worst failure available
/// here: a capture that writes an artifact its own [`read_manifest`]
/// refuses. The per-entry headroom is the only free number and this is what
/// measures it, so changing the entry SHAPE reds here rather than in the
/// field.
///
/// One tree is serialized and the total extrapolated, because serializing
/// [`MAX_TREE_COUNT`] maximal trees is ~40 MB of JSON for a constant this
/// can establish from one.
#[test]
fn the_manifest_bound_admits_a_maximal_tree_manifest() {
    let entries: Vec<CapturedTreeEntry> = (0..MAX_TREE_ENTRIES)
        .map(|index| {
            // The widest path `cas` produces: `<2 hex>/<64 hex>`.
            let hex = format!("{index:064x}");
            CapturedTreeEntry {
                path: format!("{}/{hex}", &hex[0..2]),
                digest: Some("f".repeat(64)),
                byte_len: u64::MAX,
            }
        })
        .collect();
    let tree = CapturedTree {
        name: "cas".to_string(),
        root: AssetRoot::MainDataDir,
        tier: DurabilityTier::Durable,
        entry_count: entries.len() as u64,
        total_byte_len: u64::MAX,
        entry_digest: Some("f".repeat(64)),
        entries,
    };
    let serialized = serde_json::to_vec_pretty(&tree).expect("serialize a maximal tree") as Vec<u8>;
    let per_entry = serialized.len() as u64 / MAX_TREE_ENTRIES as u64;
    assert!(
        per_entry <= MAX_TREE_ENTRY_MANIFEST_BYTES,
        "one maximal `cas` entry serializes to ~{per_entry} bytes and \
         `MAX_TREE_ENTRY_MANIFEST_BYTES` allows {MAX_TREE_ENTRY_MANIFEST_BYTES}. Raise the \
         headroom (which raises `MAX_MANIFEST_BYTES` with it) rather than leaving a capture \
         able to write a manifest `read_manifest` refuses"
    );
    assert!(
        (MAX_TREE_COUNT as u64) * (serialized.len() as u64) + FLAT_MANIFEST_BYTES
            <= MAX_MANIFEST_BYTES,
        "a manifest holding {MAX_TREE_COUNT} maximal trees must fit inside \
         `MAX_MANIFEST_BYTES`"
    );
}

/// A tree entry path may not escape its own root, and the refusal is by
/// STRUCTURE rather than by a blocklist of spellings.
#[test]
fn a_tree_entry_path_cannot_escape_its_root() {
    for hostile in [
        "../../etc/shadow",
        "..",
        "/etc/shadow",
        "ab/../../../etc/shadow",
        "ab//cd",
        "ab/./cd",
        "",
        "ab\\cd",
    ] {
        let error = tree_entry_relative_path("cas", hostile)
            .expect_err("a hostile tree entry path must be refused");
        assert!(
            error.to_string().contains("unsafe"),
            "the refusal for {hostile:?} must say what is wrong: {error}"
        );
    }

    // COUNTERFACTUAL — the shape `CasStore::blob_path` actually produces is
    // accepted, so the refusals above are about traversal and not about the
    // check rejecting everything.
    let ok = tree_entry_relative_path("cas", "ab/abcdef").expect("a real CAS path is accepted");
    assert_eq!(ok, PathBuf::from("ab").join("abcdef"));
}

/// The FIRST of the two mechanisms that close the intermediate-component
/// escape, on its own.
///
/// `a_symlink_inside_a_member_path_destroys_nothing_outside_the_artifact`
/// proves the operator-visible property and deliberately does not say which
/// mechanism fired. This says: a `CasObject` member path whose component
/// count is not 2 is refused, and it is refused by a check that reads the
/// STRING, so it can run before the parent exists and before a byte moves.
///
/// The `PathOpaque` arm is the non-vacuity half. It must admit every shape —
/// an opaque tree's member paths are whatever the source directory holds —
/// which is why one mechanism was not enough and [`ProvenDir`] is the other.
#[test]
fn a_cas_member_path_shape_the_addressing_rule_cannot_produce_is_refused() {
    for shape in ["ab", "aa/bb/member", "a/b/c/d/e", "ab/cd/"] {
        let error =
            verify_member_path_shape(TreeMemberAddressing::CasObject, "cas", shape, "backup")
                .expect_err("a shape `blob_relative_path` cannot emit must be refused");
        assert!(
            error.to_string().contains("path components"),
            "the refusal for {shape:?} must name the shape rule: {error}"
        );
        // …and the SAME shape is admitted for an opaque tree, so the refusal
        // is the addressing rule and not a bound on depth.
        verify_member_path_shape(TreeMemberAddressing::PathOpaque, "opaque", shape, "backup")
            .expect("an opaque tree's member paths are the source directory's, not this rule's");
    }

    // COUNTERFACTUAL — the shape `CasStore::blob_path` actually produces.
    verify_member_path_shape(
        TreeMemberAddressing::CasObject,
        "cas",
        "ab/abcdef",
        "backup",
    )
    .expect("a real CAS member path is accepted");
}

/// The SECOND mechanism, on its own: a symlink at ANY level of a member's
/// parent path is refused by the `openat(2)` walk, including a level no
/// caller ever names.
///
/// `open_member_parents` walks `aa/bb` one component at a time from a proven
/// root, so `aa` — which the path-based form only ever RESOLVED, never
/// checked, because `capture_tree` hands it the member's parent `aa/bb` —
/// is opened with `O_NOFOLLOW` and refused with `ELOOP`. The
/// [`ProvenDir`] doc carries the measured artifact this closes.
///
/// Driven directly rather than through a capture because the shape check
/// above would refuse this member first: the point of two mechanisms is that
/// EITHER closes the exploit, and that is only demonstrable by exercising
/// each with the other out of the way.
#[cfg(unix)]
#[test]
fn a_proven_directory_walk_refuses_a_symlink_at_any_level() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let escape = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(escape.path().join("bb")).unwrap();
    symlink(escape.path(), root.path().join("aa")).unwrap();

    let proven = ProvenDir::open(
        root.path(),
        "backup",
        "the fixture root is a real directory",
    )
    .expect("a real directory opens");
    // BOTH directions. `ParentWalk::Create` is the capture's and the restore
    // TARGET's; `ParentWalk::Existing` is the two READ sides'.
    for walk in [ParentWalk::Create, ParentWalk::Existing] {
        let mut opened = BTreeMap::new();
        let mut budget = DirectoryBudget::new();
        let error = open_member_parents(
            &proven,
            &mut opened,
            Path::new("aa/bb"),
            walk,
            &mut budget,
            "backup",
            "a capture may not write members through a symlink out of the artifact",
        )
        .expect_err("an INTERMEDIATE component that is a symlink must be refused");
        assert!(
            error.to_string().contains("is not a real directory")
                && error
                    .to_string()
                    .contains(&root.path().join("aa").display().to_string()),
            "the refusal must name the level that broke the rule under {walk:?}, and said: \
             {error}"
        );
        // The escape already holds `bb`, which is what made the path form's
        // `mkdir` return `EEXIST` and its lstat answer "a real directory". The
        // walk must leave it exactly as it found it.
        assert_eq!(
            entry_names_in(escape.path()),
            vec!["bb".to_string()],
            "and NOTHING may be created through the link under {walk:?}"
        );
    }

    // NON-VACUITY — the same walk over real directories creates and proves
    // every level, once, and hands back a descriptor per level.
    let mut opened = BTreeMap::new();
    let mut budget = DirectoryBudget::new();
    open_member_parents(
        &proven,
        &mut opened,
        Path::new("cc/dd"),
        ParentWalk::Create,
        &mut budget,
        "backup",
        "unused",
    )
    .expect("a walk over real components must create and prove each of them");
    assert_eq!(
        opened.keys().cloned().collect::<Vec<_>>(),
        vec![PathBuf::from("cc"), PathBuf::from("cc").join("dd")],
        "each level is cached by its root-relative path so a shard is made once"
    );
    assert!(root.path().join("cc").join("dd").is_dir());

    // A RE-walk of the same parent is a cache hit.
    //
    // A length assertion on `opened` here would be UNFALSIFIABLE: with the
    // `opened.contains_key` short-circuit removed entirely — i.e. with the
    // descriptor cache doing nothing — it still passes, because `opened` is a
    // `BTreeMap` keyed by root-relative path and a re-walk can only re-insert the
    // same two keys. It would be arithmetic on the `assert_eq!(opened.keys(), …)`
    // above.
    //
    // The property IS covered, falsifiably, by
    // `a_tree_spanning_more_directories_than_descriptors_is_refused_not_left_to_emfile`:
    // its final arm re-walks `d0` when the cache is already full, so a walk
    // that stopped serving cache hits reds there.
    open_member_parents(
        &proven,
        &mut opened,
        Path::new("cc/dd"),
        ParentWalk::Create,
        &mut budget,
        "backup",
        "unused",
    )
    .expect("re-walking a proven parent is a cache hit");
}

/// [`ParentWalk::Existing`] opens a level and NEVER creates one.
///
/// The read direction's whole contract: a reader that can `mkdirat` is a
/// reader that mutates somebody else's artifact, and one that silently
/// creates a missing shard would turn *"this member is not in the artifact"*
/// into a directory and a later, less specific failure.
#[cfg(unix)]
#[test]
fn the_read_direction_of_the_walk_creates_nothing_and_refuses_what_is_absent() {
    let root = tempfile::tempdir().unwrap();
    let proven = ProvenDir::open(root.path(), "restore", "the fixture root").expect("open");

    let mut opened = BTreeMap::new();
    let mut budget = DirectoryBudget::new();
    let error = open_member_parents(
        &proven,
        &mut opened,
        Path::new("ab"),
        ParentWalk::Existing,
        &mut budget,
        "restore",
        "a restore may not read members through a link out of the artifact",
    )
    .expect_err("a level the artifact does not hold must be refused, never created");
    assert!(
        error.to_string().contains("does not exist")
            && error
                .to_string()
                .contains(&root.path().join("ab").display().to_string()),
        "the refusal must name the level that is absent: {error}"
    );
    assert!(
        entry_names_in(root.path()).is_empty(),
        "and the READ direction must create NOTHING: {:?}",
        entry_names_in(root.path())
    );

    // COUNTERFACTUAL — the identical call in the WRITE direction creates it,
    // so the refusal above is bought by the direction and not by the fixture.
    let mut opened = BTreeMap::new();
    open_member_parents(
        &proven,
        &mut opened,
        Path::new("ab"),
        ParentWalk::Create,
        &mut budget,
        "backup",
        "unused",
    )
    .expect("the write direction creates a missing level");
    assert_eq!(entry_names_in(root.path()), vec!["ab".to_string()]);

    // …and now the read direction finds it.
    let mut opened = BTreeMap::new();
    let mut budget = DirectoryBudget::new();
    open_member_parents(
        &proven,
        &mut opened,
        Path::new("ab"),
        ParentWalk::Existing,
        &mut budget,
        "restore",
        "unused",
    )
    .expect("the read direction opens a level that is really there");
    assert_eq!(
        opened.keys().cloned().collect::<Vec<_>>(),
        vec![PathBuf::from("ab")]
    );
}

/// The descriptor a [`ProvenDir`] holds is a RESOURCE, and the tree that
/// spans more directories than the bound is refused rather than left to
/// fail on `EMFILE` mid-write.
///
/// The shipped `cas` row cannot reach this — 256 possible shards, and
/// [`verify_member_path_shape`] forces two components — so the bound is
/// driven directly, at the bound, rather than by materializing 1,025
/// directories through a capture.
///
/// The bound is read from [`tree_member_directory_budget`] rather than typed,
/// which is what makes this test the same test on a host with a different
/// `RLIMIT_NOFILE`.
/// `the_directory_bound_is_derived_from_the_descriptor_limit_and_not_set_at_it`
/// is what checks the derivation itself.
#[cfg(unix)]
#[test]
fn a_tree_spanning_more_directories_than_descriptors_is_refused_not_left_to_emfile() {
    let limit = tree_member_directory_budget();
    let root = tempfile::tempdir().unwrap();
    let proven = ProvenDir::open(root.path(), "backup", "the fixture root").expect("open");
    let mut opened = BTreeMap::new();
    let mut budget = DirectoryBudget::new();
    for index in 0..limit {
        open_member_parents(
            &proven,
            &mut opened,
            Path::new(&format!("d{index}")),
            ParentWalk::Create,
            &mut budget,
            "backup",
            "unused",
        )
        .expect("every directory up TO the bound is admitted");
    }
    assert_eq!(opened.len(), limit);

    let error = open_member_parents(
        &proven,
        &mut opened,
        Path::new("one-too-many"),
        ParentWalk::Create,
        &mut budget,
        "backup",
        "unused",
    )
    .expect_err("the directory past the bound must be refused");
    assert!(
        error.to_string().contains("bounded maximum of")
            && error.to_string().contains("directories")
            && error.to_string().contains("RLIMIT_NOFILE"),
        "the refusal must name the bound it hit AND where the bound comes from, so an \
         operator whose host limit is the binding constraint knows the remedy: {error}"
    );

    // NON-VACUITY — a directory already in the cache is still served past
    // the bound, so the bound counts DISTINCT directories and does not turn
    // into a member-count limit. This is also the only falsifiable check in
    // the module that the cache is a cache: with the `contains_key`
    // short-circuit removed, this call allocates a descriptor past the bound
    // and reds.
    open_member_parents(
        &proven,
        &mut opened,
        Path::new("d0"),
        ParentWalk::Create,
        &mut budget,
        "backup",
        "unused",
    )
    .expect("an already-proven directory is a cache hit, not a new descriptor");
}

/// The bound counts descriptors ACROSS the caches one operation holds, not
/// within each.
///
/// # The bad state, driven directly
///
/// [`activate_captured_tree`] holds two caches — the artifact's shards and
/// the target's — and they SHARE one budget. Two caches at `budget` each
/// would be `2 * budget` descriptors held at once, which is the `EMFILE` the
/// bound exists to convert into a refusal, admitted from inside the bound.
/// The arm below is the shape that would pass under per-cache budgets: fill
/// one cache to the limit, then ask a SECOND cache for its first directory.
///
/// `a_two_sided_restore_under_a_low_descriptor_limit_is_refused_by_name_not_by_emfile`
/// drives the same property through the real product path under a real
/// lowered `RLIMIT_NOFILE`; this one pins the arithmetic without materializing
/// a thousand directories twice.
#[cfg(unix)]
#[test]
fn one_operation_s_two_shard_caches_share_one_descriptor_budget() {
    let limit = tree_member_directory_budget();
    let root = tempfile::tempdir().unwrap();
    let first_root = ProvenDir::open(root.path(), "restore", "the fixture root").expect("open");
    let second = root.path().join("second");
    std::fs::create_dir(&second).unwrap();
    let second_root = ProvenDir::open(&second, "restore", "the fixture root").expect("open");

    // ONE budget, shared, exactly as `activate_captured_tree` shares it.
    let mut budget = DirectoryBudget::new();
    let mut first: BTreeMap<PathBuf, ProvenDir> = BTreeMap::new();
    for index in 0..limit {
        open_member_parents(
            &first_root,
            &mut first,
            Path::new(&format!("d{index}")),
            ParentWalk::Create,
            &mut budget,
            "restore",
            "unused",
        )
        .expect("every directory up TO the joint bound is admitted");
    }
    assert_eq!(first.len(), limit);

    let mut other: BTreeMap<PathBuf, ProvenDir> = BTreeMap::new();
    let error = open_member_parents(
        &second_root,
        &mut other,
        Path::new("first-of-the-second-cache"),
        ParentWalk::Create,
        &mut budget,
        "restore",
        "unused",
    )
    .expect_err(
        "a SECOND cache under the same operation must be refused once the joint bound is \
         reached; a per-cache bound admits 2x the budget and reaches EMFILE inside the bound",
    );
    assert!(
        error.to_string().contains("bounded maximum of")
            && error
                .to_string()
                .contains("A restore walks the artifact AND the target"),
        "the refusal must say that both sides count against one number, because an operator \
         reading it will otherwise raise the shard count and hit it again: {error}"
    );
    assert!(
        other.is_empty(),
        "and nothing may be opened into the second cache"
    );

    // NON-VACUITY — a FRESH budget admits the same call, so the refusal is
    // the joint count and not the second root being unusable.
    let mut fresh = DirectoryBudget::new();
    open_member_parents(
        &second_root,
        &mut other,
        Path::new("first-of-the-second-cache"),
        ParentWalk::Create,
        &mut fresh,
        "restore",
        "unused",
    )
    .expect("a separate operation gets its own budget");
    assert_eq!(other.len(), 1);
}

/// A real two-sided restore under a real lowered `RLIMIT_NOFILE` is refused
/// BY NAME rather than by `EMFILE`.
///
/// # Why a child process, and why the arithmetic test is not enough
///
/// `one_operation_s_two_shard_caches_share_one_descriptor_budget` drives the
/// counting; it cannot show that the counting is what the PRODUCT path does
/// under a limit the kernel is really enforcing. On a host reporting a soft
/// limit of 1,048,576, no in-process assertion can observe the defect — the
/// blindness that would let a flat `1024` pass as "a bound". `setrlimit(2)`
/// is process-wide, so the lowered limit lives in a disposable child, exactly
/// as `owner_only_publication`'s
/// `recovery_uses_constant_descriptors_under_low_nofile_limit` does.
///
/// # The bad state
///
/// [`activate_captured_tree`] holds two caches. At `RLIMIT_NOFILE=384` the
/// derived budget is 352, a 200-shard tree passes a PER-CACHE check twice,
/// and the process then holds 400 directory descriptors plus the roots and
/// the member in flight — `EMFILE`, from inside the bound whose entire
/// purpose is to convert that into a named refusal. The assertion is on the
/// error TEXT for that reason: both forms fail, and only one of them tells
/// the operator what to do.
#[cfg(unix)]
#[test]
fn a_two_sided_restore_under_a_low_descriptor_limit_is_refused_by_name_not_by_emfile() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    const ARTIFACT: &str = "KATA_BACKUP_LOW_NOFILE_ARTIFACT";
    const TARGET: &str = "KATA_BACKUP_LOW_NOFILE_TARGET";
    const LIMIT: &str = "KATA_BACKUP_LOW_NOFILE_LIMIT";
    const TEST_PATH: &str = "store::backup::tests::a_two_sided_restore_under_a_low_descriptor_limit_is_refused_by_name_not_by_emfile";
    // 200 distinct shards: 2x is over the budget a 384 limit derives (352),
    // and 1x is comfortably under it, which is exactly the gap a per-cache
    // bound cannot see.
    const SHARDS: usize = 200;

    // ---- CHILD -------------------------------------------------------
    if let (Some(artifact), Some(target), Some(limit)) = (
        std::env::var_os(ARTIFACT),
        std::env::var_os(TARGET),
        std::env::var_os(LIMIT),
    ) {
        let limit: u64 = limit.to_string_lossy().parse().expect("a numeric limit");
        let original = getrlimit(Resource::Nofile);
        assert!(
            original.maximum.is_none_or(|hard| hard >= limit),
            "the hard limit must admit the lowered soft limit"
        );
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(limit),
                maximum: original.maximum,
            },
        )
        .expect("lowering a soft limit is always permitted");
        match restore_data_dir(Path::new(&artifact), Path::new(&target), None) {
            Ok(_) => println!("CHILD-OK"),
            Err(error) => println!("CHILD-ERR {error}"),
        }
        return;
    }

    // ---- PARENT ------------------------------------------------------
    let source = tempfile::tempdir().unwrap();
    {
        let connection = rusqlite::Connection::open(source.path().join("operational.db"))
            .expect("open the fixture database");
        connection
            .execute_batch("CREATE TABLE proof (v TEXT); INSERT INTO proof VALUES ('x');")
            .unwrap();
    }
    let planted = {
        use crate::store::cas::{CasStore, INLINE_THRESHOLD};
        let cas = CasStore::open(source.path().join("cas.db"), source.path().join("cas"))
            .expect("open cas");
        let mut shards: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut seed: u64 = 0;
        while shards.len() < SHARDS && seed < 100_000 {
            let mut payload = vec![0_u8; INLINE_THRESHOLD + 1];
            payload[0..8].copy_from_slice(&seed.to_le_bytes());
            let id = cas.put(&payload).expect("put a file-backed object");
            shards.insert(id.to_string()[0..2].to_string());
            seed += 1;
        }
        cas.checkpoint().expect("checkpoint");
        shards.len()
    };
    assert_eq!(
        planted, SHARDS,
        "the fixture must span exactly {SHARDS} shards"
    );

    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let run = |limit: u64, target: &Path| -> String {
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("the test executable"));
        // Inherit this test's per-uid inspection hold: the child is the same test
        // binary, inside our window by construction.
        kata_test_utils::inspection_lock::inherit(&mut child);
        let output = child
            .arg("--exact")
            .arg(TEST_PATH)
            .arg("--nocapture")
            .env(ARTIFACT, artifact.path())
            .env(TARGET, target)
            .env(LIMIT, limit.to_string())
            .output()
            .expect("run the lowered-limit child");
        assert!(
            output.status.success(),
            "the child must complete rather than abort: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("CHILD-"))
            .expect("the child must report an outcome")
            .to_string()
    };

    // NON-VACUITY FIRST — the same artifact, the same target shape, at a
    // limit the joint peak fits under. Without this arm the refusal below is
    // satisfiable by a fixture that cannot restore at all.
    let generous = tempfile::tempdir().unwrap();
    assert_eq!(
        run(1024, generous.path()),
        "CHILD-OK",
        "a {SHARDS}-shard tree restores at RLIMIT_NOFILE=1024, whose derived budget (992) \
         admits the JOINT peak of {}",
        SHARDS * 2
    );

    let tight = tempfile::tempdir().unwrap();
    let outcome = run(384, tight.path());
    assert!(
        outcome.contains("bounded maximum of")
            && outcome.contains("A restore walks the artifact AND the target")
            && outcome.contains("RLIMIT_NOFILE"),
        "at RLIMIT_NOFILE=384 the refusal must NAME the joint bound and the remedy: {outcome}"
    );
    assert!(
        !outcome.contains("Too many open files"),
        "and it must not be EMFILE — a per-cache bound admits 2x the budget and reaches the \
         kernel limit from inside the bound that exists to prevent exactly that: {outcome}"
    );
}

/// [`read_bounded_handle`] refuses at the bound rather than reading to EOF.
///
/// # The bad state
///
/// [`load_or_reset_restore_journal`] was `std::fs::read` — no bound at all,
/// the one read on the restore path using neither
/// [`read_regular_file_bounded`] nor a proven descriptor. The arm below is a
/// file one byte over the bound, which the shipped form read whole.
#[test]
fn a_bounded_handle_read_refuses_the_byte_past_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");

    std::fs::write(&path, vec![b'x'; 64]).unwrap();
    let inside = read_bounded_handle(File::open(&path).unwrap(), &path, 64, "probe")
        .expect("a file AT the bound is admitted");
    assert_eq!(inside.len(), 64);

    std::fs::write(&path, vec![b'x'; 65]).unwrap();
    let error = read_bounded_handle(File::open(&path).unwrap(), &path, 64, "probe")
        .expect_err("one byte past the bound must be refused, not read");
    assert!(
        error.to_string().contains("exceeds bounded maximum 64"),
        "the refusal must name the bound: {error}"
    );
}

/// [`activate_captured_tree`] refuses a symlinked SHARD in the artifact on
/// its OWN, with [`verify_captured_tree_sources`] out of the way.
///
/// # Why this is not covered by the end-to-end test
///
/// Both restore entry points run `verify_captured_tree_sources` first, so
/// through `restore_data_dir` the refusal always comes from there and this
/// function's own source walk is never the thing being measured. That is the
/// same *"an asymmetry that holds by accident of call order is one refactor
/// away from not holding"* argument
/// `a_restore_places_nothing_through_a_symlink_inside_a_member_path` makes,
/// so the property is pinned directly.
///
/// The RED, measured on the shipped binary: with the verify pass reached at
/// all, `<artifact>/trees/cas/<shard>` a symlink out of the artifact made
/// `preflight_restore_artifact` AND `restore_data_dir` return `Ok` while
/// every authoritative CAS byte was read from outside the artifact.
#[cfg(unix)]
#[test]
fn tree_activation_reads_no_member_through_a_symlinked_shard_in_the_artifact() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    let payload = vec![0x5A_u8; crate::store::cas::INLINE_THRESHOLD + 1];
    // `member` is the tree-relative MEMBER PATH derived from production's
    // `crate::store::cas::blob_relative_path_of_address`, and the shard is read
    // back off it — so the layout is spelled once, in `cas`. A hand-spelled
    // layout would be a SECOND definition that rots when the self-describing
    // address (`<shard>/<64 hex>.<function>`) moves. COST: the test does not
    // independently state the shard rule; that is
    // `the_cas_blob_layout_shards_on_the_first_two_bytes_and_falls_back_rather_than_panicking`'s
    // job and it was never this one's.
    let member = {
        let cas = crate::store::cas::CasStore::open(
            source.path().join("cas.db"),
            source.path().join("cas"),
        )
        .expect("open cas");
        let id = cas.put(&payload).expect("put");
        cas.checkpoint().expect("checkpoint");
        crate::store::cas::blob_relative_path_of_address(&kata_types::cache::CasAddress::blake3(id))
    };
    let shard_name = member
        .split('/')
        .next()
        .expect("a member path shards")
        .to_owned();
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let tree = manifest.trees.first().expect("a captured tree").clone();

    // Move the shard OUT of the artifact and leave a link behind. The bytes
    // are intact and correctly addressed; only their location is a lie.
    let escape = tempfile::tempdir().unwrap();
    let shard = artifact
        .path()
        .join(TREES_SUBDIR)
        .join("cas")
        .join(&shard_name);
    let moved = escape.path().join("relocated");
    std::fs::rename(&shard, &moved).unwrap();
    symlink(&moved, &shard).unwrap();

    let target = tempfile::tempdir().unwrap();
    let error = activate_captured_tree(
        artifact.path(),
        target.path(),
        &tree,
        DurabilityTier::Durable,
        &mut |_, _| Ok(()),
    )
    .expect_err("activation may not read a member through a link out of the artifact");
    assert!(
        error.to_string().contains("is not a real directory")
            && error.to_string().contains(&shard.display().to_string()),
        "the refusal must name the level that broke the rule: {error}"
    );
    assert!(
        !target.path().join("cas").join(&member).exists(),
        "and NOT ONE byte read from outside the artifact may reach the target"
    );

    // NON-VACUITY — the same call over the unmoved artifact places the
    // object, so the refusal is bought by the link and not by the fixture.
    std::fs::remove_file(&shard).unwrap();
    std::fs::rename(&moved, &shard).unwrap();
    let clean = tempfile::tempdir().unwrap();
    activate_captured_tree(
        artifact.path(),
        clean.path(),
        &tree,
        DurabilityTier::Durable,
        &mut |_, _| Ok(()),
    )
    .expect("an unobstructed artifact activates");
    assert_eq!(
        std::fs::read(clean.path().join("cas").join(&member)).unwrap(),
        payload,
        "and the object really lands"
    );
}

/// The descriptor bound is DERIVED from this host's soft `RLIMIT_NOFILE`,
/// and is therefore strictly below it.
///
/// # The defect this pins, and why it cannot be pinned on a high-limit host
///
/// A flat `const … = 1024` is the common default soft `RLIMIT_NOFILE` on Linux —
/// so on a default-limits host the descriptors run out BEFORE the bound fires
/// and the operator gets exactly the `EMFILE`-mid-write failure the bound exists
/// to prevent.
///
/// **On a host reporting 1,048,576, every assertion of the form "the budget leaves
/// the reserve free under the real limit" passes for a flat constant too.** So the
/// derivation is fed the DEFAULT limit directly, where a flat constant reds by
/// construction — it does not read its input.
#[cfg(unix)]
#[test]
fn the_directory_bound_is_derived_from_the_descriptor_limit_and_not_set_at_it() {
    // THE ARM THAT REDS FOR A FLAT CONSTANT. 1,024 is the common Linux
    // default.
    let at_the_common_default = tree_member_directory_budget_from(Some(1024));
    assert!(
        at_the_common_default < 1024,
        "a host whose soft RLIMIT_NOFILE is the common 1,024 default must get a bound BELOW \
         it: a bound AT the limit fires only after the limit does, and the operator gets the \
         EMFILE-mid-write failure the bound exists to convert into a named refusal. Derived: \
         {at_the_common_default}"
    );
    assert_eq!(
        at_the_common_default,
        1024 - usize::try_from(TREE_MEMBER_DIRECTORY_RESERVE).unwrap(),
        "and the gap is the stated reserve, not an arbitrary haircut"
    );
    // …and the shipped `cas` row's 256 shards still fit under it, so
    // deriving the bound is not a new way to refuse an ordinary capture.
    assert!(
        at_the_common_default >= 256,
        "the shipped `cas` row spans up to 256 shards and must still capture on a \
         default-limits host; derived: {at_the_common_default}"
    );

    // A tiny limit derives a tiny bound rather than the ceiling.
    assert_eq!(tree_member_directory_budget_from(Some(200)), 168);

    // THE ARM THAT REDS FOR A 128 RESERVE. A 222-shard capture is a shape
    // the map's future `PathOpaque` row produces, its MEASURED peak is 230
    // open descriptors, and at `ulimit -n 282` the host can finish it. A
    // reserve of 128 derives 154 and REFUSES
    // it, which is the same defect as admitting work the host cannot do,
    // pointed the other way.
    let at_a_tight_limit = tree_member_directory_budget_from(Some(282));
    assert!(
        at_a_tight_limit >= 222,
        "a host whose soft RLIMIT_NOFILE is 282 must still admit a 222-shard tree whose \
         measured peak is 230; derived: {at_a_tight_limit}"
    );
    // …and it is still strictly below the limit, so the bound still fires
    // before the kernel does. Both halves, or the arm above is satisfiable
    // by deleting the bound.
    assert!(
        at_a_tight_limit < 282,
        "and it must stay BELOW the limit: {at_a_tight_limit}"
    );
    // A generous limit is capped by the ceiling rather than trusted.
    assert_eq!(
        tree_member_directory_budget_from(Some(1_048_576)),
        TREE_MEMBER_DIRECTORY_CEILING
    );
    // `RLIM_INFINITY`.
    assert_eq!(
        tree_member_directory_budget_from(None),
        TREE_MEMBER_DIRECTORY_CEILING
    );

    // And the SHIPPED function is wired to this host's real limit, which is
    // the one thing the arms above cannot show.
    assert_eq!(
        tree_member_directory_budget(),
        tree_member_directory_budget_from(
            rustix::process::getrlimit(rustix::process::Resource::Nofile).current
        )
    );
}

/// The shipped budget really READS `RLIMIT_NOFILE`, measured by lowering it.
///
/// The arms in
/// `the_directory_bound_is_derived_from_the_descriptor_limit_and_not_set_at_it`
/// pin the arithmetic; this pins the wiring, which is the half a pure
/// function cannot show. `setrlimit(2)` is process-wide, and this is safe
/// only because nextest runs every test in its OWN process — the limit is
/// restored immediately afterwards regardless, so a run under a
/// threads-in-one-process runner narrows the window rather than relying on
/// it. The budget is cached in a `OnceLock`, so this must be the first call
/// in its process; nothing else in this module calls it at load time.
#[cfg(unix)]
#[test]
fn the_shipped_budget_reads_this_process_s_real_descriptor_limit() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let original = getrlimit(Resource::Nofile);
    let lowered = Rlimit {
        current: Some(1024),
        maximum: original.maximum,
    };
    setrlimit(Resource::Nofile, lowered).expect("lowering a soft limit is always permitted");
    let observed = tree_member_directory_budget();
    setrlimit(Resource::Nofile, original).expect("restore the original limit");

    assert_eq!(
        observed,
        1024 - usize::try_from(TREE_MEMBER_DIRECTORY_RESERVE).unwrap(),
        "the budget must come from the limit the kernel reports for THIS process; the \
         original soft limit here is {:?}, so a budget derived from that instead would be \
         {}",
        original.current,
        TREE_MEMBER_DIRECTORY_CEILING
    );
}

/// The names directly inside `dir`, sorted.
#[cfg(unix)]
fn entry_names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read the directory")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
        .collect();
    names.sort();
    names
}

/// `cas/tmp` is NOT captured, and the exclusion is measured against a real
/// walk rather than asserted from the constant.
///
/// A `.part` file is the residue of a blob write that did not complete: it
/// has no content address, no `cas_objects` row, and nothing can ever
/// reference it. Capturing it would put bytes into an artifact that no
/// shipped mechanism reclaims from a restored directory, and would record a
/// digest over what may be a torn prefix.
#[test]
fn the_cas_scratch_root_is_never_a_tree_member() {
    let dir = tempfile::tempdir().unwrap();
    let cas = dir.path().join("cas");
    std::fs::create_dir_all(cas.join("tmp")).unwrap();
    std::fs::create_dir_all(cas.join("ab")).unwrap();
    std::fs::write(cas.join("tmp").join("abcd.1.0.part"), b"half a blob").unwrap();
    std::fs::write(cas.join("ab").join("abcd"), b"a real object").unwrap();

    let mut entries = Vec::new();
    walk_tree_entries(&cas, "cas", "", 0, MAX_TREE_ENTRIES, &mut entries).expect("walk the tree");
    assert_eq!(
        entries,
        vec!["ab/abcd".to_string()],
        "the walk must carry the object and not the in-flight scratch"
    );

    // COUNTERFACTUAL — the SAME `tmp` directory under a tree with no
    // scratch exemption IS walked, so the exclusion is the named rule and
    // not an accident of the walk skipping directories it cannot read.
    let mut unexempt = Vec::new();
    walk_tree_entries(
        &cas,
        "some-other-tree",
        "",
        0,
        MAX_TREE_ENTRIES,
        &mut unexempt,
    )
    .expect("walk");
    assert_eq!(
        unexempt,
        vec!["ab/abcd".to_string(), "tmp/abcd.1.0.part".to_string()],
        "the scratch skip is keyed on the tree NAME; a second tree must state its own reason \
         rather than inherit CAS's"
    );
}

/// An interrupted RESTORE's residue is not a tree member either — and for
/// a content-addressed tree that is the difference between residue and a
/// failed backup.
///
/// [`activate_captured_tree`] streams into `<member>.restore-tmp` inside the
/// shard and unlinks it on every error path it can observe. A power loss is
/// not one of them, so a shard can hold one. It has no `cas_objects` row,
/// nothing references it, and `CasStore` never looks for it — it is exactly
/// what [`TREE_SCRATCH_SUBDIRS`] describes for `cas/tmp`, one level down.
///
/// Capturing it is not harmless pollution: [`verify_member_address`] binds a
/// member's bytes to its path, so a `.restore-tmp` does not hash to the path it sits at, so
/// a captured one would fail the whole backup over crash residue the store
/// already ignores. That is the availability cliff this skip exists to
/// prevent, which is why it lives beside the check that would otherwise
/// create it.
#[test]
fn an_interrupted_restores_residue_is_never_a_tree_member() {
    let dir = tempfile::tempdir().unwrap();
    let cas = dir.path().join("cas");
    std::fs::create_dir_all(cas.join("ab")).unwrap();
    std::fs::write(cas.join("ab").join("abcd"), b"a real object").unwrap();
    std::fs::write(
        cas.join("ab").join(format!("abcd{RESTORE_TMP_SUFFIX}")),
        b"a torn prefix of one",
    )
    .unwrap();
    std::fs::write(
        cas.join("ab").join(format!("efgh{CAPTURE_TMP_SUFFIX}")),
        b"and the capture side's",
    )
    .unwrap();

    let mut entries = Vec::new();
    walk_tree_entries(&cas, "cas", "", 0, MAX_TREE_ENTRIES, &mut entries).expect("walk the tree");
    assert_eq!(
        entries,
        vec!["ab/abcd".to_string()],
        "a shard's in-flight scratch must not become a captured member"
    );
}

/// An oversized tree REPORTS the bound and never hands back a prefix.
///
/// # Not a refusal
///
/// Refusing is right about the PREFIX and wrong about the SCOPE:
/// [`capture_tree`] runs before any database copy, so an error from it would fail
/// the entire `kata backup`, and a node with more than [`MAX_TREE_ENTRIES`]
/// file-backed objects could not back up its DATABASES — a partial success turned
/// into a total failure, inverting *degrade capacity, refuse correctness*. [`TreeCapture`] carries
/// the full argument and the counter-case.
///
/// What holds, and is the half a refusal would get right: `out`
/// must never be treated as a usable list. It holds a PREFIX, and a capture
/// over a prefix would produce an artifact whose manifest claims an
/// authoritative tree it holds part of.
///
/// Driven at a bound of 2 rather than [`MAX_TREE_ENTRIES`] — see
/// [`walk_tree_entries`] for why the cap is a parameter. The COUNTERFACTUAL
/// is the load-bearing half: the same three files under a bound of 3 walk
/// fine, so the outcome is the bound and not the fixture.
#[test]
fn an_oversized_tree_walk_reports_the_bound_and_yields_no_usable_list() {
    let dir = tempfile::tempdir().unwrap();
    let cas = dir.path().join("cas");
    std::fs::create_dir_all(cas.join("ab")).unwrap();
    for name in ["aaaa", "bbbb", "cccc"] {
        std::fs::write(cas.join("ab").join(name), b"object").unwrap();
    }

    let mut prefix = Vec::new();
    assert_eq!(
        walk_tree_entries(&cas, "cas", "", 0, 2, &mut prefix).expect(
            "an oversized tree is a CAPACITY fact, not an I/O failure, and must not surface \
             as an error that fails the whole backup"
        ),
        WalkOutcome::OverEntryBound,
        "the walk must report the bound so the caller can omit the tree and NAME the omission"
    );
    assert!(
        prefix.len() <= 2,
        "the walk stopped at the bound and `out` is a prefix; a caller that captured from it \
         would write an artifact claiming an authoritative tree it holds part of. It held {prefix:?}"
    );

    // COUNTERFACTUAL — one more of headroom and the same tree walks whole.
    let mut accepted = Vec::new();
    assert_eq!(
        walk_tree_entries(&cas, "cas", "", 0, 3, &mut accepted).expect("a tree at the bound walks"),
        WalkOutcome::Complete
    );
    assert_eq!(
        accepted,
        vec![
            "ab/aaaa".to_string(),
            "ab/bbbb".to_string(),
            "ab/cccc".to_string()
        ]
    );
}

/// The whole `kata backup` SURVIVES an oversized tree, and the artifact it
/// writes claims nothing it does not hold.
///
/// This is the product-level half of the rule [`TreeCapture`] argues, and it
/// is asserted at the seam that decides it: `capture_tree` is called with a
/// bound of 1 over a two-member tree, and the databases still land.
///
/// # The bad state first
///
/// The pre-fix `capture_tree` returned `Err` here, and `backup_data_dir`
/// propagated it before copying a single database. The baseline is therefore
/// the ORDER, which is what made the blast radius the whole product: the
/// assertion below that `stores/` holds the databases is exactly what the
/// pre-fix binary could not satisfy, because it never reached them.
#[test]
fn an_oversized_tree_is_omitted_and_the_databases_are_still_captured() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use crate::store::cas::{CasStore, INLINE_THRESHOLD};

    let source = tempfile::tempdir().unwrap();
    {
        // REAL objects through `CasStore::put`. A hand-written file under
        // `cas/` is not a CAS object — its bytes do not hash to its path —
        // and the counterfactual below would then be measuring the address
        // refusal instead of the bound.
        let cas = CasStore::open(source.path().join("cas.db"), source.path().join("cas")).unwrap();
        for seed in 0..2_u8 {
            cas.put(&vec![0xD0 ^ seed; INLINE_THRESHOLD + 1 + usize::from(seed)])
                .unwrap();
        }
        cas.checkpoint().unwrap();
    }
    Connection::open(source.path().join("operational.db"))
        .unwrap()
        .execute_batch("CREATE TABLE t (v INTEGER);")
        .unwrap();

    let artifact = tempfile::tempdir().unwrap();
    let outcome = backup_data_dir_with_hooks(
        source.path(),
        artifact.path(),
        None,
        TreeBounds {
            entries: 1,
            ..TreeBounds::PRODUCTION
        },
        || {},
        |_name| {},
    )
    .expect(
        "an oversized tree is a capacity fact; failing the whole backup over it would leave \
         the operator with NO artifact for databases that were perfectly capturable",
    );
    let manifest = outcome.manifest;

    assert!(
        manifest.tree_roots.is_empty() && manifest.trees.is_empty(),
        "the artifact must not claim a tree it does not carry: {manifest:?}"
    );
    assert!(
        manifest
            .databases
            .iter()
            .any(|name| name == "operational.db"),
        "THE POINT: the databases are captured. The pre-fix path returned an error from the \
         tree pass, which runs FIRST, so it never reached them. It carried {:?}",
        manifest.databases
    );
    assert!(
        artifact
            .path()
            .join(STORES_SUBDIR)
            .join("operational.db")
            .is_file(),
        "and the bytes are really there, not merely named"
    );
    assert!(
        !manifest
            .capture_order
            .as_ref()
            .expect("a v2 capture carries a token")
            .entries()
            .iter()
            .any(|entry| entry.asset == "cas"),
        "the consistency token orders assets the artifact HOLDS; an entry for an omitted one \
         would make the recorded capture order a fiction"
    );

    // NAMED, through the completeness machinery and not a second channel.
    let verdict = manifest_completeness(&manifest);
    assert!(
        verdict.missing_authoritative.contains(&"cas"),
        "the completeness verdict both operator reports print must name the omission: \
         {verdict:?}"
    );
    // NO CLASS ASSERTION HERE, deliberately. A class assertion would be vacuous:
    // the same seam with the SAME source at `TreeBounds::PRODUCTION` — the
    // counterfactual at the bottom of this test — yields `omitted = []`,
    // `tree_roots = ["cas"]` and the IDENTICAL class.
    //
    // The cause is structural and is stated and measured at
    // `structural_inventory_alone_cannot_earn_recoverable`: this ordinary
    // snapshot's structural adapter cannot assess it above `DataSnapshot`, so the
    // class cannot vary with an omission and no test of an omission can
    // learn anything from it. The honest assertion is the one above —
    // `missing_authoritative` names `cas` — which the counterfactual flips.
    assert!(
        format!("{verdict}").contains("cas [MainDataDir]"),
        "and the RENDERING must name it with the durable root a recovery has to resolve: \
         {verdict}"
    );

    // The REASON is carried out of the capture rather than logged into a
    // dispatcher nobody installed. `kata_backup_names_the_omitted_tree_and_the_bound_that_omitted_it`
    // is what proves it reaches an operator's screen; this proves the
    // producer exists and names the bound it hit.
    assert_eq!(
        outcome
            .omitted
            .iter()
            .map(|omitted| omitted.name.as_str())
            .collect::<Vec<_>>(),
        vec!["cas"],
        "the capture must report the asset it degraded: {:?}",
        outcome.omitted
    );
    assert!(
        outcome.omitted[0].reason.contains("bounded maximum of 1"),
        "and the reason must name the bound that omitted it, not merely that one was hit: \
         {:?}",
        outcome.omitted[0].reason
    );

    // COUNTERFACTUAL — the same source at a bound its tree fits inside
    // captures it, so the omission is the bound and not the fixture.
    let roomy = tempfile::tempdir().unwrap();
    let captured = backup_data_dir_with_hooks(
        source.path(),
        roomy.path(),
        None,
        TreeBounds::PRODUCTION,
        || {},
        |_name| {},
    )
    .expect("a tree inside the bound captures");
    assert!(
        captured.omitted.is_empty(),
        "a capture that hit no bound must report no omission: {:?}",
        captured.omitted
    );
    let captured = captured.manifest;
    assert_eq!(captured.tree_roots, vec!["cas".to_string()]);
    assert!(
        !manifest_completeness(&captured)
            .missing_authoritative
            .contains(&"cas"),
        "and then it is NOT reported missing"
    );
}

/// The tree pass reaches `cas` and does NOT reach `vcs.jj_repo`, by SHAPE.
///
/// The jj repo's capture is deferred (no shipped mechanism resolves its root),
/// and the exclusion here is structural — `AssetLocation::ConfigDeclared` is
/// not `DataDirTree` — rather than a name in a list that a later edit could
/// helpfully "fix".
#[test]
fn the_tree_pass_reaches_cas_and_recovery_evidence_not_the_jj_repo() {
    let reachable: Vec<&str> = capturable_tree_assets()
        .map(|asset| asset.location.name())
        .collect();
    assert_eq!(reachable, vec!["cas", "recovery-evidence"]);
    assert!(
        restorable_tree_asset("vcs.jj_repo").is_none(),
        "a manifest claiming the jj repo must be refused, not restored into a guessed root"
    );
    assert!(restorable_tree_asset("cas").is_some());
    assert!(
        restorable_tree_asset("recovery-generations").is_none(),
        "`recovery-generations` is a `DataDirTree` row and is `CaptureRule::Excluded`; the \
         filter must need BOTH conditions"
    );
}

/// The entry digest covers every field of every entry, in order.
///
/// Per-member evidence over an unauthenticated index proves nothing about
/// the members the index no longer names, so each single-field mutation
/// below must move the digest.
#[test]
fn the_entry_digest_moves_for_every_single_field_edit() {
    let base = vec![
        CapturedTreeEntry {
            path: "ab/aaaa".to_string(),
            digest: Some("1".repeat(64)),
            byte_len: 7,
        },
        CapturedTreeEntry {
            path: "cd/cccc".to_string(),
            digest: Some("2".repeat(64)),
            byte_len: 9,
        },
    ];
    let baseline = tree_entry_digest(&base);
    assert_eq!(
        baseline,
        tree_entry_digest(&base.clone()),
        "the digest must be a function of the entries alone"
    );

    let mut renamed = base.clone();
    renamed[1].path = "cd/cccd".to_string();
    let mut redigested = base.clone();
    redigested[1].digest = Some("3".repeat(64));
    let mut relengthed = base.clone();
    relengthed[1].byte_len = 10;
    let mut undigested = base.clone();
    undigested[1].digest = None;
    let mut dropped = base.clone();
    dropped.pop();
    let mut reordered = base.clone();
    reordered.reverse();

    for (label, mutated) in [
        ("a renamed entry", renamed),
        ("a changed member digest", redigested),
        ("a changed member length", relengthed),
        ("a dropped member digest", undigested),
        ("a DELETED entry", dropped),
        ("a reordered list", reordered),
    ] {
        assert_ne!(
            baseline,
            tree_entry_digest(&mutated),
            "{label} must move the entry digest, or the index is editable without evidence"
        );
    }

    // The empty list is domain-separated, so it is not the digest of
    // nothing and cannot be produced by any other input to this function.
    assert_ne!(
        tree_entry_digest(&[]),
        hex_digest(blake3::hash(b"").as_bytes())
    );
}

/// A directory is unreachable to discovery by TYPE, not by extension.
///
/// The function's doc now says so; this measures it. Renaming the CAS tree
/// to `cas.db/` — the one name that would satisfy the extension filter —
/// still does not capture it, because `!file_type.is_file()` runs first.
#[test]
fn a_directory_named_like_a_database_is_still_not_discovered() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("cas")).unwrap();
    std::fs::create_dir(dir.path().join("cas.db")).unwrap();
    let discovered =
        discover_databases(dir.path()).expect("discovery over a directory-only data dir");
    assert!(
        discovered.is_empty(),
        "no directory may be discovered as a database, not even one named `cas.db`; got \
         {discovered:?}"
    );

    // COUNTERFACTUAL: a regular file at the same extension IS discovered, so
    // the emptiness above is about the entry TYPE and not about the filter.
    std::fs::write(dir.path().join("real.db"), b"").unwrap();
    assert_eq!(
        discover_databases(dir.path()).expect("discovery"),
        vec!["real.db".to_string()]
    );
}

/// Open the real disk-backed ledger wiring boot.rs uses in production:
/// `InFlightLedger::open_at` on `ledger_events.db` (the delivery event log).
fn open_ledger(data_dir: &Path) -> Arc<InFlightLedger> {
    InFlightLedger::open_at(&data_dir.join("ledger_events.db")).unwrap()
}

/// The map's ranks SUBSUME the hand-maintained [`AUTHORITATIVE_LAST`] rule, which
/// is kept as the cross-check that says so.
///
/// `backup_copy_order` does not read that list. If a future edit to
/// `DURABLE_ASSETS` demoted `operational.db` below a plane that mirrors it,
/// the copy order would silently invert and the two order tests above —
/// which feed the function fixture lists — would still be reasoning about
/// whatever the map now says. This reads the hand-maintained list and requires
/// the map to still agree with it.
#[test]
fn the_map_ranks_subsume_the_hand_maintained_authoritative_last_rule() {
    for name in AUTHORITATIVE_LAST {
        let rank = snapshot_rank_of(name)
            .unwrap_or_else(|| panic!("{name} must be classified by the durable-asset map"));
        assert!(
            rank >= SnapshotRank::Authoritative,
            "{name} was hand-maintained as an authoritative plane that copies last, and the \
             durable-asset map now ranks it {rank:?}; the derived copy order would place a \
             mirror after it"
        );
    }
    // The nucleus outranks the other authoritative plane, which is what
    // makes `operational.db` strictly last rather than merely late.
    assert!(
        snapshot_rank_of("operational.db") > snapshot_rank_of("ledger_events.db"),
        "the nucleus must outrank every other authoritative plane"
    );
}

/// An unclassified database sorts FIRST, and is absent from the consistency
/// token.
///
/// Both halves matter. Sorting it first means a database the map has never
/// heard of cannot displace one it has; leaving it out of the token means
/// the token never claims a snapshot position for an asset whose references
/// nobody has recorded. `assess_backup_class` is the mechanism that reports
/// the name, and it stays the only one.
#[test]
fn a_map_unknown_database_sorts_first_and_earns_no_rank() {
    let databases: Vec<String> = ["operational.db", "ledger_events.db", "state.db"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let order = backup_copy_order(&databases);
    assert_eq!(
        order.first(),
        Some(&"state.db"),
        "a map-unknown database must sort before every ranked one; got {order:?}"
    );
    assert!(
        snapshot_rank_of("state.db").is_none(),
        "the fixture is only meaningful while `state.db` is unclassified"
    );
}

#[test]
fn backup_copy_order_puts_authoritative_plane_last() {
    // Feed the function an order in which alphabetical sorting does NOT produce the
    // required one, to prove the policy is explicit rather than incidental.
    //
    // `ledger.db`, `events.db` and `kata.db` are MAP-UNKNOWN names kept in this
    // fixture on purpose: they exercise the unranked arm — a name the map cannot
    // place sorts FIRST, because nothing the map knows may be displaced by it. No
    // boot creates them, but `discover_databases` globs up any `*.db` a data
    // directory holds, so the ordering policy must keep handling names it neither
    // produces nor classifies.
    let databases: Vec<String> = [
        "ledger_events.db",
        "cas.db",
        "events.db",
        "kata.db",
        "ledger.db",
        "memory.db",
        "operational.db",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let order = backup_copy_order(&databases);
    // The PROPERTY, not the position. This asserted that every
    // `AUTHORITATIVE_LAST` name occupied one of the final
    // `AUTHORITATIVE_LAST.len()` slots, which was a proxy for "no derived
    // mirror is copied after its authority" and only held while the copy
    // order was that same two-level partition. Under the map-derived order
    // `cas.db` and `memory.db` are `Authoritative` too, so
    // `ledger_events.db` legitimately sits mid-order — the positional
    // assertion would fail while the property it stood for is stronger than
    // before. State the property.
    for authoritative in AUTHORITATIVE_LAST {
        let position = order
            .iter()
            .position(|name| name == authoritative)
            .unwrap_or_else(|| panic!("{authoritative} must appear in the copy order"));
        let rank = snapshot_rank_of(authoritative)
            .unwrap_or_else(|| panic!("{authoritative} must be classified by the map"));
        for (derived_position, derived) in order.iter().enumerate() {
            let Some(derived_rank) = snapshot_rank_of(derived) else {
                continue;
            };
            if derived_rank < rank {
                assert!(
                    derived_position < position,
                    "{derived} ranks {derived_rank:?}, below {authoritative}'s {rank:?}, so it \
                     must copy BEFORE it — otherwise its snapshot instant can lead the \
                     authority it mirrors; got order {order:?}"
                );
            }
        }
    }
    // `ledger.db` is MAP-UNKNOWN (the map has no row for it), so it must sort before
    // every ranked name — the same arm `state.db` exercises above. The unranked rule
    // holds against every ranked plane rather than against one.
    let ledger_pos = order.iter().position(|n| *n == "ledger.db").unwrap();
    assert!(
        snapshot_rank_of("ledger.db").is_none(),
        "the fixture is only meaningful while `ledger.db` is unclassified"
    );
    for (position, name) in order.iter().enumerate() {
        if snapshot_rank_of(name).is_some() {
            assert!(
                ledger_pos < position,
                "a map-unknown `ledger.db` must sort before the ranked {name}; got order \
                 {order:?}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn backup_stays_on_one_physical_source_after_parent_alias_retarget() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let first_parent = root.path().join("first");
    let second_parent = root.path().join("second");
    let first_data = first_parent.join("data");
    let second_data = second_parent.join("data");
    std::fs::create_dir_all(&first_data).unwrap();
    std::fs::create_dir_all(&second_data).unwrap();
    for (path, value) in [(&first_data, 1_i64), (&second_data, 2_i64)] {
        let connection = rusqlite::Connection::open(path.join("state.db")).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TABLE proof (value INTEGER NOT NULL); INSERT INTO proof VALUES ({value});"
            ))
            .unwrap();
    }

    let alias = root.path().join("selected");
    symlink(&first_parent, &alias).unwrap();
    let output = root.path().join("backup");
    backup_data_dir_with_hooks(
        &alias.join("data"),
        &output,
        None,
        TreeBounds::PRODUCTION,
        || {
            std::fs::remove_file(&alias).unwrap();
            symlink(&second_parent, &alias).unwrap();
        },
        |_name| {},
    )
    .map(|outcome| outcome.manifest)
    .expect("backup remains bound to its canonical source");

    let copied = rusqlite::Connection::open(output.join(STORES_SUBDIR).join("state.db"))
        .unwrap()
        .query_row("SELECT value FROM proof", [], |row| row.get::<_, i64>(0))
        .unwrap();
    assert_eq!(
        copied, 1,
        "backup must not cross into the retargeted source"
    );
}

/// The operational source is copied after delivery metadata. A real admission
/// in that interval must survive in the captured operational database.
#[test]
fn backup_captures_operational_admission_after_delivery_copy() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let artifact = tempfile::tempdir().unwrap();
    let _ledger = open_ledger(source.path());
    let operational = crate::OperationalDb::open(source.path().join("operational.db")).unwrap();
    let execution_id = Ulid::new();
    backup_data_dir_with_hooks(
        source.path(),
        artifact.path(),
        None,
        TreeBounds::PRODUCTION,
        || {},
        |name| {
            if name == "ledger_events.db" {
                operational
                    .submit_execution(
                        execution_id,
                        &crate::ProgramRecord {
                            program_hash: kata_types::primitives::ContentHash::new([17; 32]),
                            schema_version: 4,
                            program_json: b"{}".to_vec(),
                        },
                        &crate::InvocationRecord {
                            schema_version: 1,
                            kind: crate::InvocationKind::Workflow,
                            admission_digest: kata_types::identity_algebra::AdmissionDigest(
                                kata_types::primitives::ContentHash::new([17; 32]),
                            ),
                            invocation_json: b"{}".to_vec(),
                        },
                    )
                    .unwrap();
            }
        },
    )
    .unwrap();
    let captured =
        Connection::open(artifact.path().join(STORES_SUBDIR).join("operational.db")).unwrap();
    assert_eq!(
        captured
            .query_row("SELECT COUNT(*) FROM programs", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        captured
            .query_row("SELECT COUNT(*) FROM transitions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
