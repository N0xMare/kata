//! The execution record's metering under the one engine counts each capsule
//! stage ONCE.
//!
//! A capsule attempt reaches the record twice: through the assignment
//! population the record builder folds (its completing frame's output) and
//! through the accepted occurrence outputs the executor's record read overlays.
//! The witness for "how many stages ran" is a second, read-only rusqlite handle
//! on `operational.db` — the raw `attempts` rows.

use super::common::*;

use kata_program::execution_program::compile_starlark_execution_program;
use kata_types::execution::ExecutionStatus;
use ulid::Ulid;

const TWO_STAGE_PACK: &str = r#"
draft = stage(
    id = "draft",
    agent = "default",
    prompt = "draft it",
)
review = stage(
    id = "review",
    agent = "default",
    prompt = "review it",
    depends_on = ["draft"],
)
workflow("metering-two-stage", root = [draft, review])
"#;

/// The rig's mock agent reports no cost (`MeteredCost::Unavailable`), so every
/// stage that ran is one UNMETERED stage: the record's count equals the raw
/// census of capsule attempts, and each stage is named once.
///
/// **Watched red**: before the overlay skipped population-folded stages the
/// record reported `unmetered_stages: 4` and named `draft` and `review` twice
/// each for this two-stage run.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_oci_record_meters_each_capsule_stage_once() {
    kata_types::node_profile::mark_node_installed();
    let stack = boot_executor();
    let program = compile_starlark_execution_program(TWO_STAGE_PACK, "two-stage.star", &[])
        .expect("the two-stage pack compiles under oci");
    let id = stack
        .executor
        .submit_execution_program(program)
        .expect("the pack submits under oci");
    let record = wait_terminal(&stack.executor, &id).await;
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "record: {record:?}"
    );
    let execution_id = Ulid::from_string(&id).expect("execution id");

    let conn = rusqlite::Connection::open_with_flags(
        stack
            .op_path
            .as_deref()
            .expect("the stack's db is file-backed"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second read-only handle on operational.db");
    let mut statement = conn
        .prepare(
            "SELECT stage_id FROM attempts WHERE execution_id = ?1 AND executor = 'worker' \
             ORDER BY stage_id",
        )
        .expect("prepare the raw capsule census");
    let raw_stages: Vec<String> = statement
        .query_map([execution_id.to_bytes().as_slice()], |row| row.get(0))
        .expect("query the raw capsule census")
        .collect::<Result<_, _>>()
        .expect("decode the raw capsule census");
    assert_eq!(raw_stages, vec!["draft", "review"]);

    let metering = &record.metering;
    assert_eq!(
        metering.unmetered_stages + metering.authoritative_stages + metering.estimated_stages,
        u32::try_from(raw_stages.len()).expect("a small census"),
        "one metering fold per capsule stage that ran: {metering:?}"
    );
    let mut named: Vec<&str> = metering
        .unmetered
        .iter()
        .map(|stage| stage.stage.as_str())
        .collect();
    named.sort_unstable();
    assert_eq!(named, raw_stages, "each unmetered stage is named once");
}
