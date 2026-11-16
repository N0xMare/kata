use djs_embed::{Builder, Data, HostFn, Snapshot, Source};

const BOOTSTRAP: &str = include_str!("bootstrap.js");
const CODE_TOOLS: &str = include_str!("code-tools.mjs");
const CODE_VALUES: &str = include_str!("code-values.mjs");

pub(crate) const BOOTSTRAP_MODULE: &str = "nanocode:bootstrap";
pub(crate) const PREPARE_CELL: &str = "prepareCell";
pub(crate) const RUN_CELL: &str = "runCell";

pub(crate) const TOOL: u32 = 1;
pub(crate) const CONTENT: u32 = 2;
pub(crate) const TEXT: u32 = 3;
pub(crate) const LOAD: u32 = 4;
pub(crate) const NOTIFY: u32 = 5;
pub(crate) const YIELD: u32 = 6;
pub(crate) const SET_TIMEOUT: u32 = 7;
pub(crate) const CLEAR_TIMEOUT: u32 = 8;
pub(crate) const VALUE: u32 = 9;
pub(crate) const SETTLED: u32 = 10;
pub(crate) const NEXT: u32 = 11;
pub(crate) const CATALOG: u32 = 12;
pub(crate) const QUIET: u32 = 13;
pub(crate) const EXIT: u32 = 14;
pub(crate) const STORE: u32 = 15;
pub(crate) const SETTLE: u32 = 16;

const HOST_FNS: [(u32, &str); 14] = [
    (TOOL, "__nanocodeTool"),
    (CONTENT, "__nanocodeContent"),
    (TEXT, "__nanocodeText"),
    (LOAD, "__nanocodeLoad"),
    (STORE, "__nanocodeStore"),
    (NOTIFY, "__nanocodeNotify"),
    (YIELD, "__nanocodeYield"),
    (SET_TIMEOUT, "__nanocodeSetTimeout"),
    (CLEAR_TIMEOUT, "__nanocodeClearTimeout"),
    (VALUE, "__nanocodeValue"),
    (SETTLED, "__nanocodeSettled"),
    (CATALOG, "__nanocodeCatalog"),
    (EXIT, "__nanocodeExit"),
    (SETTLE, "__nanocodeSettle"),
];

pub(crate) enum Definitions<'a> {
    AtSetup(&'a str),
    PerCell,
}

pub(crate) fn builder(definitions: &Definitions<'_>, prelude_at_setup: bool) -> Builder {
    let builder = Snapshot::builder().frozen_builtins(false);
    let builder = match definitions {
        Definitions::AtSetup(definitions) => {
            builder.global("__nanocodeDefinitions", Data::from(*definitions))
        }
        Definitions::PerCell => builder,
    };
    let mut builder = builder
        .global("__nanocodePreludeAtSetup", Data::Bool(prelude_at_setup))
        .host_fn(HostFn::asynchronous(NEXT, "__nanocodeNext"))
        .setup_probe(HostFn::sync(QUIET, "__nanocodeQuiet"));
    for (id, name) in HOST_FNS {
        builder = builder.host_fn(HostFn::sync(id, name));
    }
    builder
}

pub(crate) fn bootstrap(definitions: &Definitions<'_>) -> Result<Source, String> {
    let values = CODE_VALUES
        .split_once("export const")
        .ok_or_else(|| "shared value helper export marker is missing".to_owned())?
        .0;
    let prepare = format!(
        "{}(createCodeTools, createValueHelpers())",
        BOOTSTRAP.trim_end()
    );
    let exports = match definitions {
        Definitions::AtSetup(_) => format!("export const {RUN_CELL} = {prepare};\n"),
        Definitions::PerCell => format!(
            "const prepareCellWith = {prepare};\nexport let {RUN_CELL};\nexport const {PREPARE_CELL} = (definitions) => {{ {RUN_CELL} = prepareCellWith(definitions); }};\n"
        ),
    };
    Ok(Source::module(
        BOOTSTRAP_MODULE,
        format!("{CODE_TOOLS}\n{values}\n{exports}"),
    ))
}

pub(crate) fn per_cell() -> Result<Builder, String> {
    Ok(builder(&Definitions::PerCell, false).source(bootstrap(&Definitions::PerCell)?))
}
