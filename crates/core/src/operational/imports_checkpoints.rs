//! Positive custody evidence for the offline durable-sleep cohort.
//!
//! The cohort is an execution parked EXCLUSIVELY in durable timer waits: every unsettled
//! attempt a MAIN-resolved attempt in `awaiting_timer` with its `wait_deadline_ms`, no
//! worker, no dispatch, no command, no claimed effect. A live main INPUT wait or CHILD
//! wait is refused by name — neither is a timer a restored main can resume from its own
//! rows alone (an input wait owes an operator, a child wait owes another execution) — and
//! any worker attempt is refused as live work.
use super::{
    Connection, Instant, KataError, KataResult, RecoveryReadDeadline, Ulid,
    inspect_recovery_population, recovery_deadline, storage,
};
use crate::store::backup::RecoverySleepCheckpoint;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct RecoverySleepPopulation {
    pub authority_head: u64,
    pub has_pending_imports: bool,
    pub executions: BTreeMap<Ulid, Vec<RecoverySleepCheckpoint>>,
}

/// Caller retains a read transaction. Checked-program sleep semantics are checked
/// by the runtime adapter; this layer proves exact durable custody and fences.
pub fn inspect_recovery_sleep_population(
    conn: &Connection,
    deadline: Instant,
) -> KataResult<RecoverySleepPopulation> {
    let population = inspect_recovery_population(conn, deadline)?;
    let _deadline = RecoveryReadDeadline::new(conn, deadline)?;
    let refuse = || {
        KataError::Validation("recovery requires a running execution parked exclusively in durable timer waits, with no installed schedules or buffered input".into())
    };
    let buffered: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM event_inbox WHERE accepted=0)",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    if population.has_installed_schedules || buffered {
        return Err(refuse());
    }
    let head: i64 = conn
        .query_row("SELECT COALESCE(MAX(seq),0) FROM transitions", [], |r| {
            r.get(0)
        })
        .map_err(storage)?;
    let mut result = RecoverySleepPopulation {
        authority_head: u64::try_from(head).map_err(|_| refuse())?,
        has_pending_imports: conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM recovery_imports WHERE released_at_ms IS NULL)",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?,
        executions: BTreeMap::new(),
    };
    for execution in population.nonterminal_executions {
        recovery_deadline(deadline)?;
        let state: String = conn
            .query_row(
                "SELECT state FROM execution_lifecycle WHERE execution_id=?1",
                [execution.to_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if state != "running" {
            return Err(refuse());
        }
        result.executions.insert(execution, Vec::new());
    }
    for attempt in population.unsettled_attempts {
        recovery_deadline(deadline)?;
        let row = conn.query_row(
            "SELECT a.execution_id,a.stage_id,a.attempt_ordinal,a.lease_epoch,a.wait_deadline_ms,a.source_seq, \
             p.state='awaiting_timer' AND p.source_seq=a.source_seq AND a.worker_id IS NULL \
             AND a.child_execution_id IS NULL AND a.dispatched_at_ms IS NULL AND a.finished_at_ms IS NULL \
             AND NOT EXISTS(SELECT 1 FROM attempt_commands c WHERE c.attempt_id=a.attempt_id) \
             AND NOT EXISTS(SELECT 1 FROM worker_dispatch_domains d WHERE d.attempt_id=a.attempt_id) \
             AND EXISTS(SELECT 1 FROM transitions t WHERE t.seq=a.source_seq AND t.attempt_id=a.attempt_id AND t.scope='attempt' AND t.folds_projection=1 AND t.resulting_state='awaiting_timer') \
             , a.executor, p.state \
             FROM attempts a JOIN attempt_projection p ON p.execution_id=a.execution_id AND p.stage_id=a.stage_id AND p.attempt_ordinal=a.attempt_ordinal WHERE a.attempt_id=?1",
            [attempt.to_bytes().as_slice()],
            |r| Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,Option<i64>>(4)?,r.get::<_,i64>(5)?,r.get::<_,bool>(6)?,r.get::<_,String>(7)?,r.get::<_,String>(8)?)),
        ).map_err(storage)?;
        if super::super::AttemptExecutor::from_column(&row.7)?
            != super::super::AttemptExecutor::Main
        {
            return Err(refuse());
        }
        if matches!(
            row.8.as_str(),
            "awaiting_input" | "awaiting_child_completion"
        ) {
            return Err(KataError::Validation(format!(
                "recovery refuses to capture attempt {attempt}: it is a live main {} wait, \
                 which the durable-sleep cohort cannot carry (a restored main resumes a \
                 timer from its own rows; an input wait owes an operator and a child wait \
                 owes another execution); let it resolve, or cancel its execution, before \
                 capturing",
                if row.8 == "awaiting_input" {
                    "INPUT"
                } else {
                    "CHILD-COMPLETION"
                }
            )));
        }
        let execution = super::super::ulid_from_bytes(&row.0)?;
        let Some(sleeps) = result.executions.get_mut(&execution) else {
            return Err(refuse());
        };
        if !row.6 {
            return Err(refuse());
        }
        let wait_deadline_ms = row.4.filter(|value| *value > 0).ok_or_else(refuse)?;
        sleeps.push(RecoverySleepCheckpoint {
            attempt_id: attempt,
            stage_id: row.1,
            attempt_ordinal: u32::try_from(row.2).map_err(|_| refuse())?,
            lease_epoch: u64::try_from(row.3).map_err(|_| refuse())?,
            wait_deadline_ms,
            transition_seq: u64::try_from(row.5).map_err(|_| refuse())?,
        });
    }
    if result.executions.values().any(Vec::is_empty) {
        return Err(refuse());
    }
    for sleeps in result.executions.values_mut() {
        sleeps.sort_by(|a, b| {
            a.stage_id
                .cmp(&b.stage_id)
                .then(a.attempt_id.cmp(&b.attempt_id))
        });
    }
    Ok(result)
}
