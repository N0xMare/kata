//! Integration test: every shipped `kata.toml` text — the minimal fixture, the
//! canonical example, and each TOML block the operator guide tells an operator to
//! write — parses through the closed config door.

use std::path::{Path, PathBuf};

use kata_types::config::{load_worker_config, parse_kata_config};
use kata_types::load_config_placeholder;

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn minimal_config_loads_and_validates() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal_config.toml");
    let cfg = load_config_placeholder(&path).expect("fixture should load");
    assert_eq!(cfg.node.id, "main-a");
    assert!(!cfg.workers.transports.is_empty());
    assert_eq!(cfg.api.bind, "127.0.0.1:8400");
}

/// The commented-out block of `text` that starts at the line `first` and runs while
/// lines stay commented, uncommented — `None` when `text` has no such line.
fn commented_block(text: &str, first: &str) -> Option<String> {
    let mut lines = text.lines().skip_while(|line| *line != first);
    lines.next()?;
    let mut block = format!("{}\n", &first[2..]);
    for line in lines.take_while(|line| line.starts_with("# ")) {
        block.push_str(&line[2..]);
        block.push('\n');
    }
    Some(block)
}

/// `config/kata.example.toml` parses through the closed door, and so do the two blocks
/// it ships COMMENTED OUT for the operator to fill in — `[node] environment` (with its
/// `integrity_policy`) and a `[[pricing.models]]` row — each uncommented and merged in.
/// Every live section the example writes refuses a key it does not declare, so this is
/// the proof the example spells nothing kata does not read. The example does not write
/// every section: `[git_view]` is absent (its defaults stand), and the operator guide's
/// blocks are judged by the next cell.
///
/// **Watched red:** the environment block first shipped as a multi-line inline table,
/// which TOML 1.0 (kata's parser) refuses, and this cell refused it; with
/// `integrity_policy`'s `sigs_needed` misspelled in the block, it named the key.
#[test]
fn the_example_config_parses_through_the_closed_door() {
    let path = repo_path("config/kata.example.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    parse_kata_config(&text, &path).unwrap_or_else(|error| panic!("{error}"));

    let mut document: toml::Table = toml::from_str(&text).unwrap();
    let environment = commented_block(&text, "# environment.label = \"kata-agents\"")
        .expect("the example ships a commented `[node] environment`");
    // The example elides store paths as `…`, which the store-path parser rightly
    // refuses: stand in a well-formed digest and name, so the cell judges the keys.
    let environment = environment.replace(
        "/nix/store/…",
        "/nix/store/00000000000000000000000000000000-example",
    );
    let mut node = toml::Table::new();
    node.insert(
        "node".to_owned(),
        toml::Value::Table(toml::from_str(&environment).unwrap_or_else(|error| {
            panic!("the commented environment is not TOML: {error}\n{environment}")
        })),
    );
    merge(&mut document, node);
    let pricing = commented_block(&text, "# [[pricing.models]]")
        .expect("the example ships a commented `[[pricing.models]]` row");
    merge(
        &mut document,
        toml::from_str(&pricing).unwrap_or_else(|error| {
            panic!("the commented pricing row is not TOML: {error}\n{pricing}")
        }),
    );
    let uncommented = toml::to_string(&document).unwrap();
    let config = parse_kata_config(&uncommented, &path)
        .unwrap_or_else(|error| panic!("{error}\n{uncommented}"));
    assert!(config.node.environment.is_some() && config.pricing.models.len() == 1);
}

/// Merge `fragment` into `base`, table by table — a guide block names only the keys it
/// is about, and lands in an otherwise-complete file.
fn merge(base: &mut toml::Table, fragment: toml::Table) {
    for (key, value) in fragment {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(into)), toml::Value::Table(from)) => merge(into, from),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// The operator guide's fenced `toml` blocks, in order.
fn guide_toml_blocks(guide: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut open: Option<String> = None;
    for line in guide.lines() {
        match (&mut open, line.trim_end()) {
            (None, "```toml") => open = Some(String::new()),
            (Some(block), "```") => {
                blocks.push(std::mem::take(block));
                open = None;
            }
            (Some(block), line) => {
                block.push_str(line);
                block.push('\n');
            }
            (None, _) => {}
        }
    }
    assert!(open.is_none(), "an unterminated ```toml block in the guide");
    blocks
}

/// **EVERY TOML BLOCK THE OPERATOR GUIDE TELLS AN OPERATOR TO WRITE PARSES**, through
/// the door that refuses an undeclared key: a `kata.toml` block merged into the
/// minimal fixture goes through [`parse_kata_config`], and the block headed `#
/// kata-worker config` merged into a minimal worker file goes through
/// [`load_worker_config`]. A guide that spells a key kata does not declare would send
/// the operator straight to a load refusal.
///
/// **Watched red:** with `[node] egress_allow` misspelled `egress_alow` in the guide's
/// block, this cell named it.
#[test]
fn every_operator_guide_toml_block_parses_through_the_closed_door() {
    let guide_path = repo_path("docs/product/operator-guide.md");
    let guide = std::fs::read_to_string(&guide_path).unwrap();
    let main_base: toml::Table = toml::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal_config.toml"),
        )
        .unwrap(),
    )
    .unwrap();
    let worker_base: toml::Table = toml::from_str(
        "home_node_endpoint = 'unix:///tmp/kata-worker.sock'\ncredential_path = \
         '/tmp/kata-worker.cred'\nexpected_membrane_id = '01ARZ3NDEKTSV4RRFFQ69G5FAV'\n\
         capabilities = []\n",
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();

    let blocks = guide_toml_blocks(&guide);
    assert!(
        !blocks.is_empty(),
        "no ```toml block found in {} — a scan that matches nothing proves nothing",
        guide_path.display()
    );
    let (mut main_blocks, mut worker_blocks, mut wrong) = (0, 0, Vec::new());
    for (index, block) in blocks.iter().enumerate() {
        // The guide elides a store path's digest and version as `…`, which the store
        // path parser rightly refuses: stand in a well-formed digest and name, so the
        // cell judges the keys the block spells, not the elision.
        let block = &block
            .replace(
                "/nix/store/…-",
                "/nix/store/00000000000000000000000000000000-",
            )
            .replace('…', "x");
        let fragment: toml::Table = toml::from_str(block)
            .unwrap_or_else(|error| panic!("guide block {index} is not TOML: {error}\n{block}"));
        let worker = block.starts_with("# kata-worker config");
        let mut document = if worker {
            worker_blocks += 1;
            worker_base.clone()
        } else {
            main_blocks += 1;
            main_base.clone()
        };
        merge(&mut document, fragment);
        let path: &Path = &dir.path().join(format!("block-{index}.toml"));
        let text = toml::to_string(&document).unwrap();
        std::fs::write(path, &text).unwrap();
        let parsed = if worker {
            load_worker_config(path).map(drop)
        } else {
            parse_kata_config(&text, path).map(drop)
        };
        if let Err(error) = parsed {
            wrong.push(format!("guide block {index}:\n{block}{error}"));
        }
    }
    assert!(
        main_blocks > 0 && worker_blocks > 0,
        "expected kata.toml and kata-worker blocks, found {main_blocks} and {worker_blocks}"
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n\n"));
}
