//! Immutable output storage: bytes precede a root and its referencing fact;
//! root and fact commit together. Raw chain readers retain storage identity.
use kata_types::cache::CasAddress;
use kata_types::idempotency::canonicalize_args;
use kata_types::primitives::ContentHash;
use kata_types::{KataError, KataResult};
use rusqlite::{OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ulid::Ulid;

use super::{CasRootOwner, CasRootSpec, OperationalDb, TransitionFrame};

pub(super) const OUTPUT_ROOT_PURPOSE: &str = "operational_output";
pub(super) const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const OUTPUT_TRANSITION_KINDS: &[&str] = &[
    "outcome_amended",
    "undispatched_stage_recorded",
    "undispatched_stage_settled",
    "event_accepted",
    "attempt_advanced",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputReference {
    root_id: ContentHash,
    address: String,
    size_bytes: u64,
}

type OutputRootRow = (String, Option<Vec<u8>>, String, Option<Vec<u8>>);

pub(super) struct PreparedOutput {
    encoded: Value,
    root: Option<CasRootSpec>,
}

impl PreparedOutput {
    pub(super) fn write_fields(&self, payload: &mut Map<String, Value>) {
        payload.remove("output");
        payload.remove("output_ref");
        let key = if self.root.is_some() {
            "output_ref"
        } else {
            "output"
        };
        payload.insert(key.into(), self.encoded.clone());
    }

    pub(super) fn envelope(&self) -> Value {
        let mut payload = Map::new();
        self.write_fields(&mut payload);
        Value::Object(payload)
    }

    pub(super) fn record_root(&self, tx: &Transaction<'_>) -> KataResult<()> {
        if let Some(root) = &self.root {
            super::repo::upsert_cas_root(tx, root, super::now_ms())?;
        }
        Ok(())
    }
}

fn invalid(detail: impl std::fmt::Display) -> KataError {
    KataError::Validation(format!("authoritative output: {detail}"))
}

impl OperationalDb {
    /// A compact JSON envelope is at least as large as its output value. Reuse
    /// that already-encoded bound to avoid re-encoding ordinary small outputs.
    pub(super) fn prepare_offloaded_output(
        &self,
        execution: Ulid,
        output: &Value,
        envelope_bytes: usize,
    ) -> KataResult<Option<PreparedOutput>> {
        if envelope_bytes <= crate::store::INLINE_THRESHOLD {
            return Ok(None);
        }
        let prepared = self.prepare_output(execution, output)?;
        Ok(prepared.root.is_some().then_some(prepared))
    }

    pub(super) fn prepare_output(
        &self,
        execution: Ulid,
        output: &Value,
    ) -> KataResult<PreparedOutput> {
        let bytes = canonicalize_args(output);
        if bytes.len() <= crate::store::INLINE_THRESHOLD {
            return Ok(PreparedOutput {
                encoded: output.clone(),
                root: None,
            });
        }
        if bytes.len() as u64 > MAX_OUTPUT_BYTES {
            return Err(invalid("output exceeds 64 MiB bound"));
        }
        let cas = self
            .output_cas
            .get()
            .ok_or_else(|| invalid("large output requires an explicitly bound CAS store"))?;
        let address = kata_types::cache::cas_address_for_canonical_bytes(&bytes);
        let root_id = CasRootSpec::output_object_root_id(execution, address.hash().0);
        let already_rooted = self.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM cas_roots WHERE root_id=?1)",
                [root_id.as_slice()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(invalid)
        })?;
        // Retransmission is not disaster recovery: once a fact owns these bytes,
        // a missing/corrupt object must remain a refusal, not be recreated by put.
        if already_rooted {
            cas.get_verified(&address.hash(), bytes.len() as u64, MAX_OUTPUT_BYTES)?;
        }
        let object = cas.put_durable(&bytes)?;
        let root = CasRootSpec::for_object(
            &object,
            CasRootOwner::Execution(execution),
            OUTPUT_ROOT_PURPOSE,
        );
        let reference = OutputReference {
            root_id: ContentHash::new(root.root_id()),
            address: CasAddress::blake3(object.object_id()).to_string(),
            size_bytes: object.size(),
        };
        let encoded = serde_json::to_value(reference).map_err(invalid)?;
        Ok(PreparedOutput {
            encoded,
            root: Some(root),
        })
    }

    /// Resolve output without changing the retained frame. Retain the raw frame
    /// for identity verification; resolve once before interpreting its payload.
    pub fn resolve_transition_output(
        &self,
        frame: &TransitionFrame,
    ) -> KataResult<TransitionFrame> {
        let mut resolved = frame.clone();
        resolved.payload_json =
            self.resolve_output_payload(frame.execution_id, &frame.kind, &frame.payload_json)?;
        Ok(resolved)
    }

    pub(super) fn read_output(
        &self,
        address: CasAddress,
        size: u64,
        maximum: u64,
    ) -> KataResult<Vec<u8>> {
        let cas = self
            .output_cas
            .get()
            .ok_or_else(|| invalid("referenced output requires an explicitly bound CAS store"))?;
        cas.get_verified(&address.hash(), size, maximum)
    }

    pub(super) fn resolve_output_payload(
        &self,
        execution: Ulid,
        kind: &str,
        bytes: &[u8],
    ) -> KataResult<Vec<u8>> {
        self.with_read(|conn| {
            resolve_authoritative_output_payload(
                conn,
                execution,
                kind,
                bytes,
                |address, size, maximum| self.read_output(address, size, maximum),
            )
        })
    }
}

/// Read-only decoding for both live and captured authority. The caller supplies
/// the coherent authority connection and a bounded, content-verifying byte reader;
/// this function never opens or modifies either store.
pub fn resolve_authoritative_output_payload(
    connection: &rusqlite::Connection,
    execution: Ulid,
    kind: &str,
    bytes: &[u8],
    read: impl FnMut(CasAddress, u64, u64) -> KataResult<Vec<u8>>,
) -> KataResult<Vec<u8>> {
    OutputResolver { connection, read }.payload(execution, kind, bytes)
}

/// Verify references in the named output-bearing transition kinds and recognized
/// typed worker-completion inbox envelopes in one coherent artifact/source snapshot.
/// This includes record-only output history and the inbox rows of ACCEPTED completions
/// (no completion is ever parked unaccepted: the capsule door accepts one in the
/// transaction that adopts its result), not arbitrary inbox authentication. It is an offline check, not a startup history scan. The
/// caller owns the snapshot and byte-reader deadline; bounds refuse rather than omit.
/// Inbox verification covers recognized typed worker-completion envelopes only;
/// generic IncomingEvent payloads remain opaque and do not reserve output fields.
pub fn verify_authoritative_output_references(
    connection: &rusqlite::Connection,
    deadline: std::time::Instant,
    max_rows: usize,
    read: impl FnMut(CasAddress, u64, u64) -> KataResult<Vec<u8>>,
) -> KataResult<usize> {
    let _deadline = super::RecoveryReadDeadline::new(connection, deadline)?;
    let mut resolver = OutputResolver { connection, read };
    let kinds = OUTPUT_TRANSITION_KINDS
        .iter()
        .map(|kind| format!("'{kind}'"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT execution_id,kind,CASE WHEN length(payload_json)<={MAX_OUTPUT_BYTES} THEN payload_json END FROM transitions WHERE kind IN ({kinds})
         UNION ALL SELECT execution_id,'worker_completion',CASE WHEN length(payload_json)<={MAX_OUTPUT_BYTES} THEN payload_json END FROM event_inbox
         WHERE CASE WHEN length(payload_json)>{MAX_OUTPUT_BYTES} THEN 1
                    WHEN json_valid(payload_json) THEN json_extract(payload_json,'$.kind')='worker_completion'
                    ELSE 0 END"
    );
    let mut query = connection.prepare(&sql).map_err(invalid)?;
    let mut rows = query.query([]).map_err(invalid)?;
    let mut checked = 0usize;
    while let Some(row) = rows.next().map_err(invalid)? {
        if std::time::Instant::now() >= deadline || checked >= max_rows {
            return Err(invalid(
                "output reference verification exceeded its deadline or row bound",
            ));
        }
        let execution: Vec<u8> = row.get(0).map_err(invalid)?;
        let execution = super::ulid_from_bytes(&execution)?;
        let kind: String = row.get(1).map_err(invalid)?;
        let bytes: Option<Vec<u8>> = row.get(2).map_err(invalid)?;
        let bytes = bytes.ok_or_else(|| invalid("output record exceeds the bounded read size"))?;
        resolver.payload(execution, &kind, &bytes)?;
        checked += 1;
    }
    if std::time::Instant::now() >= deadline {
        return Err(invalid(
            "output reference verification exceeded its deadline",
        ));
    }
    Ok(checked)
}

struct OutputResolver<'a, F> {
    connection: &'a rusqlite::Connection,
    read: F,
}

impl<F: FnMut(CasAddress, u64, u64) -> KataResult<Vec<u8>>> OutputResolver<'_, F> {
    fn payload(&mut self, execution: Ulid, kind: &str, bytes: &[u8]) -> KataResult<Vec<u8>> {
        if !OUTPUT_TRANSITION_KINDS.contains(&kind)
            && kind != "worker_completion"
            && super::AttemptLifecycle::from_state(kind).is_none()
        {
            return Ok(bytes.to_vec());
        }
        if kind == "outcome_amended" {
            let mut payload: Value = serde_json::from_slice(bytes).map_err(invalid)?;
            self.resolve_output_fields(execution, &mut payload)?;
            let output = payload
                .as_object_mut()
                .and_then(|p| p.remove("output"))
                .ok_or_else(|| invalid("amendment has no output"))?;
            return Ok(canonicalize_args(&output));
        }
        let mut payload: Value = serde_json::from_slice(bytes).map_err(invalid)?;
        if kind == super::UNDISPATCHED_STAGE_RECORD_KIND {
            if payload.pointer("/record/kind").and_then(Value::as_str) == Some("outcome_amended") {
                let record = payload
                    .get_mut("record")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| invalid("stage amendment has no record"))?;
                let value = record
                    .get_mut("value")
                    .ok_or_else(|| invalid("stage amendment has no value"))?;
                self.resolve_output_fields(execution, value)?;
                let output = value
                    .as_object_mut()
                    .and_then(|p| p.remove("output"))
                    .ok_or_else(|| invalid("stage amendment has no output"))?;
                *value = output;
            }
        } else if payload.get("output_ref").is_some() || payload.get("output").is_some() {
            self.resolve_output_fields(execution, &mut payload)?;
        } else {
            return Ok(bytes.to_vec());
        }
        serde_json::to_vec(&payload).map_err(invalid)
    }

    fn resolve_output_fields(&mut self, execution: Ulid, payload: &mut Value) -> KataResult<()> {
        let fields = payload
            .as_object_mut()
            .ok_or_else(|| invalid("output envelope is not an object"))?;
        let Some(reference) = fields.remove("output_ref") else {
            if fields.get("output").is_some_and(|output| {
                canonicalize_args(output).len() > crate::store::INLINE_THRESHOLD
            }) {
                return Err(invalid(
                    "oversized inline output violates the current storage contract",
                ));
            }
            return Ok(());
        };
        if fields.contains_key("output") {
            return Err(invalid(
                "inline output and CAS output are mutually exclusive",
            ));
        }
        let reference: OutputReference = serde_json::from_value(reference).map_err(invalid)?;
        let address: CasAddress = reference.address.parse().map_err(invalid)?;
        if reference.root_id.as_bytes()
            != CasRootSpec::output_object_root_id(execution, address.hash().0).as_slice()
        {
            return Err(invalid(
                "CAS output root identity is not derived from its content",
            ));
        }
        if reference.size_bytes <= crate::store::INLINE_THRESHOLD as u64
            || reference.size_bytes > MAX_OUTPUT_BYTES
        {
            return Err(invalid("CAS output length is outside the offload bounds"));
        }
        {
            let root: Option<OutputRootRow> = self.connection.query_row(
                "SELECT owner_kind,owner_execution_id,purpose,object_digest FROM cas_roots WHERE root_id=?1",
                [reference.root_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional().map_err(invalid)?;
            let Some((owner, held_execution, purpose, digest)) = root else {
                return Err(invalid("CAS output root is missing"));
            };
            if owner != "execution"
                || held_execution.as_deref() != Some(execution.to_bytes().as_slice())
                || purpose != OUTPUT_ROOT_PURPOSE
                || digest.as_deref() != Some(address.hash().as_bytes())
            {
                return Err(invalid(
                    "CAS output root disagrees with execution, purpose or content",
                ));
            }
        }
        let bytes = (self.read)(address, reference.size_bytes, MAX_OUTPUT_BYTES)?;
        if bytes.len() as u64 != reference.size_bytes
            || kata_types::cache::cas_address_for_canonical_bytes(&bytes) != address
        {
            return Err(invalid(
                "CAS output bytes disagree with the immutable descriptor",
            ));
        }
        let output: Value = serde_json::from_slice(&bytes).map_err(invalid)?;
        if canonicalize_args(&output) != bytes {
            return Err(invalid("CAS output bytes are not canonical JSON"));
        }
        fields.insert("output".into(), output);
        Ok(())
    }
}
