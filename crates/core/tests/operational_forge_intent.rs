//! The `forge_intents` plane — `crates/core/src/operational/forge_intent.rs`
//! against the real SQLite store, every outcome read back through a SECOND raw
//! rusqlite handle, never kata's own reader.
//!
//! The cells pin the plane's refused set: no intent for an attempt that is not
//! a `pending` `forge_export` (a cancel that beat the export leaves nothing to
//! issue under), no intent while another is open, no second push after a
//! performed one, a verdict written once, a receipt only ever `performed`, and
//! no resolution of an attempt holding an open intent — and the one transaction
//! a receipt and the export's result commit in.

use std::sync::Arc;

use kata_core::operational::{
    ForgeIntentEffect, ForgeIntentOutcome, ForgeIntentVerdict, ForgeVerdictSource, MainAttemptSpec,
    MainResolution, NewForgeIntent, OccurrenceBinding, WorkspaceEffectSpec,
};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::error::KataError;
use kata_types::execution::CandidateTreePin;
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::primitives::ContentHash;
use kata_types::workflow::WorkspaceEffectOp;
use ulid::Ulid;

struct Rig {
    dir: tempfile::TempDir,
    db: Arc<OperationalDb>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    Rig {
        dir,
        db: Arc::new(db),
    }
}

fn submit(rig: &Rig, execution: Ulid) {
    let program = ProgramRecord {
        program_hash: ContentHash::new([0xC1; 32]),
        schema_version: 4,
        program_json: b"{}".to_vec(),
    };
    let invocation = InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
            [0xA2; 32],
        )),
        invocation_json: b"{}".to_vec(),
    };
    match rig
        .db
        .submit_execution(execution, &program, &invocation)
        .unwrap()
    {
        SubmitOutcome::Submitted { .. } | SubmitOutcome::AlreadySubmitted => {}
    }
    rig.db.mark_running(execution).unwrap();
}

/// A raw read-only handle on the plane's file — the oracle that shares no
/// code with the writers under test.
fn raw(rig: &Rig) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        rig.dir.path().join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("the raw reader opens the operational db")
}

/// `(effect_index, effect, lease, base, verdict, verdict_by)` of every intent
/// the attempt recorded, read raw.
type RawIntent = (
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn raw_intents(rig: &Rig, attempt: Ulid) -> Vec<RawIntent> {
    let conn = raw(rig);
    let mut statement = conn
        .prepare(
            "SELECT effect_index, effect, lease, base, verdict, verdict_by FROM forge_intents \
             WHERE attempt_id = ?1 ORDER BY effect_index",
        )
        .unwrap();
    statement
        .query_map([attempt.to_bytes().as_slice()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn raw_state(rig: &Rig, attempt: Ulid) -> String {
    raw(rig)
        .query_row(
            "SELECT p.state FROM attempt_projection p
               JOIN attempts a
                 ON a.execution_id = p.execution_id AND a.stage_id = p.stage_id
                AND a.attempt_ordinal = p.attempt_ordinal
              WHERE a.attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

fn claim(rig: &Rig, execution: Ulid, op: WorkspaceEffectOp, path: u32) -> Ulid {
    let attempt = Ulid::new();
    let spec = MainAttemptSpec {
        stage_id: format!("ship{path}"),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xB8; 32]),
                OperationContractId(ContentHash::new([0x5F; 32])),
                OperationPath(vec![path]),
            ),
            None,
            None,
        ),
    };
    let effect = WorkspaceEffectSpec {
        op,
        label: None,
        target: format!("kata/{execution}"),
        candidate_commit: "cand".to_owned(),
        delivered_commit: "delivered".to_owned(),
        candidate_tree_id: "tree".to_owned(),
        pin: CandidateTreePin::Unpinned,
        forge: None,
        forge_remote: (op == WorkspaceEffectOp::ForgeExport).then(|| "origin".to_owned()),
    };
    rig.db
        .claim_workspace_effect_attempt(attempt, &spec, &effect, None)
        .unwrap();
    attempt
}

fn push(attempt: Ulid, lease: Option<&str>) -> NewForgeIntent<'static> {
    NewForgeIntent {
        attempt_id: attempt,
        remote: "origin",
        branch: "kata/x",
        commit: "delivered",
        effect: ForgeIntentEffect::Push {
            lease: lease.map(str::to_owned),
        },
    }
}

fn pull_request(attempt: Ulid) -> NewForgeIntent<'static> {
    NewForgeIntent {
        attempt_id: attempt,
        remote: "origin",
        branch: "kata/x",
        commit: "delivered",
        effect: ForgeIntentEffect::PullRequest {
            base: "main".to_owned(),
        },
    }
}

fn verdict(verdict: ForgeIntentVerdict, source: ForgeVerdictSource) -> ForgeIntentOutcome {
    ForgeIntentOutcome {
        verdict,
        source,
        detail: serde_json::json!({"cell": true}),
    }
}

/// **An intent is recorded only for a `pending` `forge_export` of a live
/// execution.** A push intent on a fresh export claim lands with its lease
/// (raw); the same call on a `park` attempt, and on an export the operator's
/// cancel already settled, answers `None` and writes no row — so a cancel
/// that beat the export leaves it nothing to issue under.
///
/// **Would red if:** the premise read were dropped or widened (a row on the
/// park or the cancelled export).
#[test]
fn an_intent_is_recorded_only_for_a_pending_forge_export() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);

    let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 0);
    let recorded = rig
        .db
        .record_forge_intent(&push(export, None))
        .unwrap()
        .expect("a pending export records its push intent");
    assert_eq!(recorded.id.effect_index, 0);
    assert_eq!(
        raw_intents(&rig, export),
        [(0, "push".to_owned(), None, None, None, None)],
        "one open push intent, leased on the branch's absence"
    );

    let park = claim(&rig, execution, WorkspaceEffectOp::Park, 1);
    assert!(
        rig.db
            .record_forge_intent(&push(park, Some("abc")))
            .unwrap()
            .is_none(),
        "a park is no forge export"
    );
    assert!(raw_intents(&rig, park).is_empty());

    let cancelled = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 2);
    rig.db
        .resolve_workspace_effect_attempt(
            cancelled,
            None,
            &MainResolution::Cancel {
                reason: "the operator cancelled",
                terminal_charge: None,
            },
        )
        .unwrap()
        .expect("the export's cancel resolves it");
    assert!(
        rig.db
            .record_forge_intent(&push(cancelled, None))
            .unwrap()
            .is_none(),
        "a cancelled export records no intent"
    );
    assert!(raw_intents(&rig, cancelled).is_empty());
}

/// **One open intent at a time, and no push after a performed one.** A second
/// intent while the first has no verdict is refused (`Internal`), and so is a
/// push intent once a push was performed; a push after a `not_performed`
/// verdict and the pull request after a performed push both record (raw
/// rows).
///
/// **Would red if:** either refusal were dropped.
#[test]
fn one_intent_is_open_at_a_time_and_no_push_follows_a_performed_one() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 0);

    let first = rig
        .db
        .record_forge_intent(&push(export, None))
        .unwrap()
        .unwrap();
    let error = rig
        .db
        .record_forge_intent(&push(export, None))
        .expect_err("a second intent while the first is open is refused");
    assert!(
        matches!(&error, KataError::Internal(text) if text.contains("has no verdict")),
        "{error:?}"
    );
    assert_eq!(raw_intents(&rig, export).len(), 1);

    rig.db
        .settle_forge_intent(
            first.id,
            &verdict(
                ForgeIntentVerdict::NotPerformed,
                ForgeVerdictSource::Observer,
            ),
        )
        .unwrap();
    let second = rig
        .db
        .record_forge_intent(&push(export, Some("other")))
        .unwrap()
        .expect("a fresh push intent follows a NOT PERFORMED verdict");
    assert_eq!(second.id.effect_index, 1);

    rig.db
        .settle_forge_intent(
            second.id,
            &verdict(ForgeIntentVerdict::Performed, ForgeVerdictSource::Receipt),
        )
        .unwrap();
    let pr = rig
        .db
        .record_forge_intent(&pull_request(export))
        .unwrap()
        .expect("the pull request's intent records after the push's receipt");
    assert_eq!(pr.id.effect_index, 2);
    assert_eq!(
        raw_intents(&rig, export),
        [
            (
                0,
                "push".to_owned(),
                None,
                None,
                Some("not_performed".to_owned()),
                Some("observer".to_owned())
            ),
            (
                1,
                "push".to_owned(),
                Some("other".to_owned()),
                None,
                Some("performed".to_owned()),
                Some("receipt".to_owned())
            ),
            (
                2,
                "pull_request".to_owned(),
                None,
                Some("main".to_owned()),
                None,
                None
            ),
        ]
    );

    rig.db
        .settle_forge_intent(
            pr.id,
            &verdict(
                ForgeIntentVerdict::NotPerformed,
                ForgeVerdictSource::Observer,
            ),
        )
        .unwrap();
    let error = rig
        .db
        .record_forge_intent(&push(export, Some("delivered")))
        .expect_err("no push intent follows a performed push");
    assert!(
        matches!(&error, KataError::Internal(text) if text.contains("second push intent")),
        "{error:?}"
    );
    assert_eq!(
        raw_intents(&rig, export).len(),
        3,
        "the refused intent wrote nothing"
    );
}

/// **A verdict is written once, and a receipt only ever says `performed`.**
/// A second verdict on a settled intent is refused (`Internal`) and the first
/// stands (raw); a `not_performed` receipt is refused by the table itself.
///
/// **Would red if:** the write-once predicate were dropped (the second verdict
/// overwrote the first) or the receipt CHECK were.
#[test]
fn a_verdict_is_written_once_and_a_receipt_only_says_performed() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 0);
    let intent = rig
        .db
        .record_forge_intent(&push(export, None))
        .unwrap()
        .unwrap();

    let error = rig
        .db
        .settle_forge_intent(
            intent.id,
            &verdict(
                ForgeIntentVerdict::NotPerformed,
                ForgeVerdictSource::Receipt,
            ),
        )
        .expect_err("a receipt that says not performed is refused");
    assert!(
        matches!(&error, KataError::Storage(text) if text.contains("CHECK")),
        "{error:?}"
    );
    rig.db
        .settle_forge_intent(
            intent.id,
            &verdict(
                ForgeIntentVerdict::Unclassified,
                ForgeVerdictSource::Observer,
            ),
        )
        .unwrap();
    let error = rig
        .db
        .settle_forge_intent(
            intent.id,
            &verdict(ForgeIntentVerdict::Performed, ForgeVerdictSource::Observer),
        )
        .expect_err("a second verdict is refused");
    assert!(
        matches!(&error, KataError::Internal(text) if text.contains("written once")),
        "{error:?}"
    );
    assert_eq!(
        raw_intents(&rig, export)[0].4.as_deref(),
        Some("unclassified"),
        "the first verdict stands"
    );
}

/// **No attempt resolves past an open intent, and the export's result commits
/// with its verdict.** With the push intent open, both resolve doors refuse
/// and the attempt stays `pending` (raw); `resolve_forge_export_attempt` with
/// the intent's verdict resolves it, verdict and terminal in one commit.
///
/// **Would red if:** either door's open-intent refusal were dropped (the
/// attempt resolved over an intent that still owes its observer's answer).
/// **An open intent counts its observer's unanswered reads and keeps its
/// command's error once; neither is written on a settled intent.** Two
/// unanswered reads accumulate (raw `unanswered_reads` 2, the last error and
/// its time beside it); the command's error is written once — a second, and
/// an empty one, are refused. Once a verdict is written, both writers refuse
/// and the row is left as it was.
#[test]
fn an_open_intent_counts_unanswered_reads_and_keeps_its_command_error_once() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 0);
    let intent = rig
        .db
        .record_forge_intent(&push(export, None))
        .unwrap()
        .unwrap();
    let raw_row = |rig: &Rig| -> (i64, Option<i64>, Option<String>, Option<String>) {
        raw(rig)
            .query_row(
                "SELECT unanswered_reads, last_unanswered_at_ms, last_read_error, command_error \
                 FROM forge_intents WHERE attempt_id = ?1",
                rusqlite::params![export.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    };
    assert_eq!(raw_row(&rig), (0, None, None, None));

    rig.db
        .record_forge_command_error(intent.id, "the push failed")
        .unwrap();
    for refused in ["a second error", ""] {
        let error = rig
            .db
            .record_forge_command_error(intent.id, refused)
            .expect_err("the command error is written once, and never empty");
        assert!(matches!(error, KataError::Internal(_)), "{error:?}");
    }
    assert_eq!(
        rig.db
            .record_unanswered_forge_read(intent.id, "first")
            .unwrap()
            .count,
        1
    );
    let second = rig
        .db
        .record_unanswered_forge_read(intent.id, "second")
        .unwrap();
    assert_eq!(second.count, 2);
    let (count, at_ms, last_error, command_error) = raw_row(&rig);
    assert_eq!(count, 2);
    assert_eq!(at_ms, Some(second.last_at_ms));
    assert_eq!(last_error.as_deref(), Some("second"));
    assert_eq!(command_error.as_deref(), Some("the push failed"));

    rig.db
        .settle_forge_intent(
            intent.id,
            &verdict(
                ForgeIntentVerdict::NotPerformed,
                ForgeVerdictSource::Observer,
            ),
        )
        .unwrap();
    let before = raw_row(&rig);
    let error = rig
        .db
        .record_unanswered_forge_read(intent.id, "after the verdict")
        .expect_err("a settled intent counts no read");
    assert!(matches!(error, KataError::Internal(_)), "{error:?}");
    assert_eq!(
        raw_row(&rig),
        before,
        "the refused write left the row as it was"
    );
}

#[test]
fn no_attempt_resolves_past_an_open_intent() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 0);
    let intent = rig
        .db
        .record_forge_intent(&push(export, None))
        .unwrap()
        .unwrap();
    let fail = MainResolution::Fail {
        reason: "workspace_effect_unclassified: the remote did not answer",
        terminal_charge: None,
    };

    for error in [
        rig.db
            .resolve_workspace_effect_attempt(export, None, &fail)
            .expect_err("the effect door refuses an open intent"),
        rig.db
            .resolve_forge_export_attempt(export, None, &fail)
            .expect_err("the export door refuses an open intent it is not settling"),
    ] {
        assert!(
            matches!(&error, KataError::Internal(text) if text.contains("has no verdict")),
            "{error:?}"
        );
    }
    assert_eq!(raw_state(&rig, export), "pending");

    rig.db
        .resolve_forge_export_attempt(
            export,
            Some((
                intent.id,
                &verdict(
                    ForgeIntentVerdict::Unclassified,
                    ForgeVerdictSource::Observer,
                ),
            )),
            &fail,
        )
        .unwrap()
        .expect("the export resolves with its verdict");
    assert_eq!(raw_state(&rig, export), "failed");
    assert_eq!(
        raw_intents(&rig, export)[0].4.as_deref(),
        Some("unclassified")
    );
}

/// **The head kata last pushed to a branch is the newest performed push of
/// the execution to it.** A not-performed push, another branch's push and
/// another remote's push are not it.
///
/// **Would red if:** the read ignored the verdict, the branch, the remote, or
/// the order.
#[test]
fn the_last_performed_push_is_the_newest_performed_push_to_that_branch() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    assert_eq!(
        rig.db
            .last_performed_forge_push(execution, "origin", "kata/x")
            .unwrap(),
        None
    );
    let performed = verdict(ForgeIntentVerdict::Performed, ForgeVerdictSource::Receipt);
    let not_performed = verdict(
        ForgeIntentVerdict::NotPerformed,
        ForgeVerdictSource::Observer,
    );
    let settle_push = |path: u32, remote: &str, branch: &str, commit: &str, outcome| {
        let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, path);
        let intent = rig
            .db
            .record_forge_intent(&NewForgeIntent {
                attempt_id: export,
                remote,
                branch,
                commit,
                effect: ForgeIntentEffect::Push { lease: None },
            })
            .unwrap()
            .unwrap();
        rig.db.settle_forge_intent(intent.id, outcome).unwrap();
    };
    settle_push(0, "origin", "kata/x", "first", &performed);
    settle_push(1, "origin", "kata/x", "second", &performed);
    settle_push(2, "origin", "kata/x", "third", &not_performed);
    settle_push(3, "origin", "kata/y", "fourth", &performed);
    settle_push(4, "upstream", "kata/x", "fifth", &performed);
    assert_eq!(
        rig.db
            .last_performed_forge_push(execution, "origin", "kata/x")
            .unwrap()
            .as_deref(),
        Some("second")
    );
}

/// **Terminal intent fences the intent, and the drain leaves an open one
/// open.** Once the execution is `terminalizing`, the pull request's intent
/// answers `None` and writes nothing, the push intent staying open (raw). The
/// publication's drain then cancels the attempt over that open intent, which
/// stays open: nothing can resolve the attempt any more —
/// `resolve_forge_export_attempt` is refused by name and writes nothing, the
/// verdict it carried included — and the open intent is the record of what
/// may have been issued. The push's receipt alone still commits on it
/// (`settle_forge_intent`): a verdict records what the remote did, whoever
/// settled the attempt.
///
/// **Would red if:** the premise admitted a terminalizing execution (a pull
/// request intent row), or the receipt were refused on a settled attempt.
#[test]
fn a_terminalizing_export_records_no_intent_and_the_drain_leaves_its_open_one() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let export = claim(&rig, execution, WorkspaceEffectOp::ForgeExport, 0);
    let pushed = rig
        .db
        .record_forge_intent(&push(export, None))
        .unwrap()
        .unwrap();
    rig.db
        .begin_terminalization(
            execution,
            kata_core::operational::LifecycleState::Cancelled,
            br#"{"kind":"cancelled","detail":"cancelled under an open forge intent"}"#,
        )
        .unwrap();
    let receipt = verdict(ForgeIntentVerdict::Performed, ForgeVerdictSource::Receipt);
    assert!(
        rig.db
            .record_forge_intent(&pull_request(export))
            .unwrap()
            .is_none(),
        "a terminalizing execution's export records no intent"
    );
    assert_eq!(
        raw_intents(&rig, export),
        [(0, "push".to_owned(), None, None, None, None)],
        "no pull-request row, and the push intent still open"
    );

    rig.db.finish_terminalization(execution).unwrap();
    assert_eq!(raw_state(&rig, export), "cancelled");
    assert_eq!(
        raw_intents(&rig, export)[0].4,
        None,
        "the drain leaves the open intent open"
    );

    let error = rig
        .db
        .resolve_forge_export_attempt(
            export,
            Some((pushed.id, &receipt)),
            &MainResolution::Fail {
                reason: "too late",
                terminal_charge: None,
            },
        )
        .expect_err("nothing resolves after the outcome is published");
    assert!(
        matches!(&error, KataError::Validation(text) if text.contains("nothing was written")),
        "{error:?}"
    );
    assert_eq!(
        raw_intents(&rig, export)[0].4,
        None,
        "the refused resolve wrote no verdict"
    );
    rig.db
        .settle_forge_intent(pushed.id, &receipt)
        .expect("the push's receipt commits on a settled attempt");
    assert_eq!(raw_intents(&rig, export)[0].4.as_deref(), Some("performed"));
}
