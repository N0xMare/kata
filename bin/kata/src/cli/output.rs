//! CLI output sink: human text vs. structured JSON.
//!
//! The global `--format` selects one of two modes for every command that has
//! a human renderer: [`OutputFormat::Human`] (the text renderers) or
//! [`OutputFormat::Json`]. Under `json`, an operation's own CLI face (`kata
//! check`) emits the schema'd, versioned [`OpEnvelope`] carrying that
//! operation's typed response — the document the MCP and REST faces return —
//! through [`emit_ok`]; every other command emits its own JSON document bare
//! through [`emit_record`]. No such command takes a per-command `--json`.

use std::io::Write as _;

use anyhow::{Result, anyhow};
use kata_op_contract::{OpEnvelope, OpResponse};
use serde::Serialize;

/// The top-level output format, selected by the global `--format` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text (the default).
    #[default]
    Human,
    /// Structured `OpEnvelope` JSON.
    Json,
}

impl OutputFormat {
    /// Whether this format selects the structured JSON path.
    #[must_use]
    pub fn is_json(self) -> bool {
        matches!(self, OutputFormat::Json)
    }
}

/// Emit a success `OpEnvelope` carrying `response` as pretty-printed JSON on
/// stdout, tagged with the operation `response` is the response of.
///
/// The bound is the guarantee: only an [`OpResponse`] — one of the contract's
/// ten response types, a sealed set — can be enveloped, and the `op` tag is the
/// type's own [`OpResponse::OP`], so `emit_ok` cannot tag a document with an
/// operation whose published `response_schema` it does not satisfy. It is the
/// CLI's one envelope builder outside the MCP binding (`cli/mcp.rs`, which
/// envelopes a dispatch's value under the operation it dispatched): the
/// `op_envelope_cli_tests` cell
/// `the_cli_builds_an_envelope_only_in_emit_ok_and_the_mcp_binding` refuses an
/// `OpEnvelope::ok`/`err` call anywhere else in `bin/kata/src`. A command whose
/// JSON is not an operation's response uses [`emit_record`].
///
/// It is NOT every `--format json` site, and the top-level `--format` help says
/// so: the operator read commands (`run list`/`show`/`output`/`current`/`wait`,
/// `status`, `health`, `version`, `workers`, `approvals`, `workspace`, `steer`)
/// emit bare records or NDJSON in every format; `run list`'s divergence is
/// deliberate and documented on `operator::run::run_list_emits_full_records`.
pub fn emit_ok<R: OpResponse>(response: &R) -> Result<()> {
    write_pretty_json(&OpEnvelope::ok(R::OP, response))
}

/// Emit a command's own JSON document, bare (no envelope), as pretty-printed
/// JSON on stdout — the `--format json` shape of every command that is not an
/// operation's face.
pub fn emit_record<T: Serialize>(document: &T) -> Result<()> {
    write_pretty_json(document)
}

fn write_pretty_json<T: Serialize>(value: &T) -> Result<()> {
    let rendered =
        serde_json::to_string_pretty(value).map_err(|e| anyhow!("formatting json: {e}"))?;
    write_stdout(format!("{rendered}\n").as_bytes())
        .map_err(|e| anyhow!("writing json to stdout: {e}"))
}

/// Write `bytes` to stdout and flush them.
///
/// A reader that closed the pipe before the end (`kata workflows schema | head`)
/// took everything it wanted, so `BrokenPipe` is success here rather than a
/// failure — the reading `repo_ignore` gives git's EPIPE. Every other write error
/// is returned.
pub(crate) fn write_stdout(bytes: &[u8]) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match handle.write_all(bytes).and_then(|()| handle.flush()) {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_op_contract::Operation;

    #[test]
    fn envelope_payload_matches_input_data() {
        // The envelope wraps the response as `data`; prove the payload is
        // preserved verbatim under the wrapper and tagged by its own type.
        let response = kata_op_contract::responses::AuthorResponse {
            config: ".kata/kata.toml".to_owned(),
            created: false,
        };
        let envelope = OpEnvelope::ok(
            <kata_op_contract::responses::AuthorResponse as OpResponse>::OP,
            &response,
        );
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["op"], Operation::Author.as_str());
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"], serde_json::to_value(&response).unwrap());
        assert!(value.get("error").is_none());
    }
}
