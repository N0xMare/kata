//! A `forge_export`'s INTENT ROWS: one per wire effect the export issues — a
//! `git push` of `kata/<exec>`, or the `gh pr create` from it (ADR 0003
//! "Effects"; ADR 0002 decisions 2 to 4, as ADR 0003 amends them).
//!
//! # The order an intent fixes
//!
//! An intent commits AFTER every step of its effect that can fail without
//! issuing it — the export's refusals and its local branch write, and for a
//! push the read of the remote's head, whose answer is the row's lease — and
//! BEFORE the effect's first byte. Its verdict is written once: by the
//! RECEIPT, in the transaction that records the effect's result, or by the
//! effect's OBSERVER when a crash or a failed command left the outcome
//! unknown. So after a crash:
//!
//! * no intent: the effect was never issued — PROVEN NOT PERFORMED;
//! * an intent with a verdict: that verdict;
//! * an intent alone: owed its observer's verdict, and nothing is issued
//!   again under it — a fresh intent follows only a `NotPerformed` verdict.
//!
//! An open intent also keeps what its verdict will rest on: the error its
//! effect's own command returned ([`OperationalDb::record_forge_command_error`],
//! written once, before the observer is asked), and the observer's reads the
//! remote did not answer ([`OperationalDb::record_unanswered_forge_read`]),
//! counted — the driver settles the intent `Unclassified` once the count
//! reaches its bound, and asks again before that.
//!
//! An intent's identity is its coordinates, [`ForgeIntentId`]: the attempt and
//! the effect's index within it (ADR 0002 decision 2), so a recovery reads the
//! very intent the crashed drive wrote, and a pull request carries it as its
//! marker. The observers themselves (the remote ref for a push, a pull
//! request carrying the intent's marker for a pull request) are the export
//! driver's, in `kata-workflow`; this plane records what they said.
//!
//! # What the writers refuse
//!
//! * [`OperationalDb::record_forge_intent`] records nothing, and answers
//!   `None`, unless its attempt is a `pending` `forge_export` main attempt of an
//!   `admitting` or `running` execution, checked in its own writer
//!   transaction: a cancel or a terminal drain that beat the export leaves no
//!   intent, so nothing is issued. It refuses (`Internal`) a new intent while
//!   another of the attempt's intents has no verdict, and a push intent once one
//!   of the attempt's pushes was performed.
//! * a verdict is written once ([`OperationalDb::settle_forge_intent`] refuses a
//!   second, `Internal`), and a receipt is only ever `Performed` (a CHECK).
//! * no `workspace_effect` attempt resolves while one of its intents has no
//!   verdict ([`OperationalDb::resolve_forge_export_attempt`] and
//!   `resolve_workspace_effect_attempt` both refuse, `Internal`). The terminal
//!   drain (`cancel_workspace_effect_attempts_in_tx`) is the one settlement
//!   that leaves an intent open: it cancels an attempt nothing can resolve any
//!   more, and the open intent stays the record of what may have been issued.
//!   A push whose command succeeded is not left open by it unless the main
//!   dies before the push's receipt: the receipt commits on its own
//!   ([`OperationalDb::settle_forge_intent`] asks no premise), whether or not
//!   a drain settled the attempt first. A push whose command returned an
//!   error and whose observer's read went unanswered stays open.

use kata_types::error::{KataError, KataResult};
use kata_types::workflow::WorkspaceEffectOp;
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::main_attempt::{MainResolution, MainResolvePremise};
use super::{AttemptLifecycle, OperationalDb};

/// Which wire effect an intent announces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgeIntentEffect {
    /// `git push` of the intent's commit to the remote's
    /// `refs/heads/<branch>`, leased on `lease`: the head the read before the
    /// intent found there (`None`: the branch was absent).
    Push {
        /// The head the pre-intent read answered — the push's lease.
        lease: Option<String>,
    },
    /// `gh pr create` from the intent's branch into `base`, its body marked
    /// with the intent's coordinates.
    PullRequest {
        /// The pull request's base branch.
        base: String,
    },
}

impl ForgeIntentEffect {
    /// The stored spelling: `push` or `pull_request`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Push { .. } => "push",
            Self::PullRequest { .. } => "pull_request",
        }
    }
}

/// An intent's identity: its attempt and the effect's index within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForgeIntentId {
    /// The issuing attempt.
    pub attempt_id: Ulid,
    /// The effect's place among the attempt's wire effects, from 0.
    pub effect_index: i64,
}

impl std::fmt::Display for ForgeIntentId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.attempt_id, self.effect_index)
    }
}

/// An intent to record: the wire effect an attempt is about to issue.
#[derive(Clone, Debug)]
pub struct NewForgeIntent<'a> {
    /// The issuing `forge_export` attempt.
    pub attempt_id: Ulid,
    /// The git remote the push goes to and the pull request is opened on.
    pub remote: &'a str,
    /// `kata/<exec>`.
    pub branch: &'a str,
    /// The commit the push sends, and the pull request's head commit.
    pub commit: &'a str,
    /// The effect and what it is bound to.
    pub effect: ForgeIntentEffect,
}

/// What an intent's verdict says about its wire effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgeIntentVerdict {
    /// The effect reached the remote.
    Performed,
    /// Nothing of the effect reached the remote.
    NotPerformed,
    /// Nobody can say: the observer read a state that answers neither way, or
    /// the remote left its reads unanswered up to the driver's bound.
    Unclassified,
}

impl ForgeIntentVerdict {
    /// The stored spelling: `performed`, `not_performed` or `unclassified`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Performed => "performed",
            Self::NotPerformed => "not_performed",
            Self::Unclassified => "unclassified",
        }
    }

    fn parse(text: &str) -> KataResult<Self> {
        match text {
            "performed" => Ok(Self::Performed),
            "not_performed" => Ok(Self::NotPerformed),
            "unclassified" => Ok(Self::Unclassified),
            other => Err(KataError::Storage(format!(
                "forge_intents.verdict `{other}` is outside the stamped vocabulary"
            ))),
        }
    }
}

/// Who gave a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgeVerdictSource {
    /// The effect's own command answered, and its result committed with the
    /// verdict.
    Receipt,
    /// The effect's observer read the remote after the outcome was left
    /// unknown.
    Observer,
}

impl ForgeVerdictSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Observer => "observer",
        }
    }

    fn parse(text: &str) -> KataResult<Self> {
        match text {
            "receipt" => Ok(Self::Receipt),
            "observer" => Ok(Self::Observer),
            other => Err(KataError::Storage(format!(
                "forge_intents.verdict_by `{other}` is outside the stamped vocabulary"
            ))),
        }
    }
}

/// A verdict on one intent, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgeIntentOutcome {
    /// What happened.
    pub verdict: ForgeIntentVerdict,
    /// Who said so.
    pub source: ForgeVerdictSource,
    /// What the verdict rests on: the receipt's answer, or what the observer
    /// read (or could not read).
    pub detail: serde_json::Value,
}

/// A recorded verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedForgeVerdict {
    /// The verdict.
    pub outcome: ForgeIntentOutcome,
    /// When it was written.
    pub at_ms: i64,
}

/// The observer's reads of an open intent's remote that went unanswered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnansweredReads {
    /// How many.
    pub count: u32,
    /// When the last one was recorded.
    pub last_at_ms: i64,
    /// What the last one failed with.
    pub last_error: String,
}

/// One recorded intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgeIntentRecord {
    /// The intent's identity — the marker a pull request's body carries.
    pub id: ForgeIntentId,
    /// The attempt's stage coordinate.
    pub stage_id: String,
    /// The git remote.
    pub remote: String,
    /// `kata/<exec>`.
    pub branch: String,
    /// The commit pushed, or the pull request's head commit.
    pub commit: String,
    /// The effect and what it is bound to.
    pub effect: ForgeIntentEffect,
    /// When the intent committed.
    pub recorded_at_ms: i64,
    /// Its verdict, once written.
    pub verdict: Option<RecordedForgeVerdict>,
    /// The error the effect's own command returned; `None` when no command
    /// answered (a crash left the outcome).
    pub command_error: Option<String>,
    /// The observer's reads the remote did not answer; `None` before the
    /// first.
    pub unanswered: Option<UnansweredReads>,
}

impl ForgeIntentRecord {
    /// `true` while the intent has no verdict.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.verdict.is_none()
    }

    /// The verdict, when one was written.
    #[must_use]
    pub fn verdict(&self) -> Option<ForgeIntentVerdict> {
        self.verdict
            .as_ref()
            .map(|recorded| recorded.outcome.verdict)
    }
}

const SELECT_INTENT: &str = "SELECT attempt_id, stage_id, effect_index, effect, remote, branch, \
     commit_sha, lease, base, recorded_at_ms, verdict, verdict_by, verdict_json, verdict_at_ms, \
     command_error, unanswered_reads, last_unanswered_at_ms, last_read_error FROM forge_intents";

fn storage(what: &str) -> impl Fn(rusqlite::Error) -> KataError + '_ {
    move |error| KataError::Storage(format!("{what}: {error}"))
}

type IntentRow = (
    Vec<u8>,
    String,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<String>,
    i64,
    Option<i64>,
    Option<String>,
);

/// What `record_forge_intent` reads of its attempt: execution, stage, projected
/// state, the execution's lifecycle state, and the claim's blob.
type IntentPremise = (Vec<u8>, String, Option<String>, Option<String>, Vec<u8>);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IntentRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
    ))
}

fn decode_row(row: IntentRow) -> KataResult<ForgeIntentRecord> {
    let (
        attempt_id,
        stage_id,
        effect_index,
        effect,
        remote,
        branch,
        commit,
        lease,
        base,
        recorded_at_ms,
        verdict,
        verdict_by,
        verdict_json,
        verdict_at_ms,
        command_error,
        unanswered_reads,
        last_unanswered_at_ms,
        last_read_error,
    ) = row;
    let effect = match (effect.as_str(), base) {
        ("push", None) => ForgeIntentEffect::Push { lease },
        ("pull_request", Some(base)) => ForgeIntentEffect::PullRequest { base },
        (other, _) => {
            return Err(KataError::Storage(format!(
                "forge_intents row names effect `{other}` with a base the CHECK refuses"
            )));
        }
    };
    let verdict = match (verdict, verdict_by, verdict_json, verdict_at_ms) {
        (None, None, None, None) => None,
        (Some(verdict), Some(source), Some(detail), Some(at_ms)) => Some(RecordedForgeVerdict {
            outcome: ForgeIntentOutcome {
                verdict: ForgeIntentVerdict::parse(&verdict)?,
                source: ForgeVerdictSource::parse(&source)?,
                detail: serde_json::from_slice(&detail).map_err(|error| {
                    KataError::Storage(format!("forge_intents.verdict_json is not JSON: {error}"))
                })?,
            },
            at_ms,
        }),
        _ => {
            return Err(KataError::Storage(
                "forge_intents row carries part of a verdict, which the CHECKs refuse".to_owned(),
            ));
        }
    };
    let unanswered = match (unanswered_reads, last_unanswered_at_ms, last_read_error) {
        (0, None, None) => None,
        (count, Some(last_at_ms), Some(last_error)) if count > 0 => Some(UnansweredReads {
            count: u32::try_from(count).map_err(|_| {
                KataError::Storage(format!(
                    "forge_intents.unanswered_reads {count} is outside u32"
                ))
            })?,
            last_at_ms,
            last_error,
        }),
        _ => {
            return Err(KataError::Storage(
                "forge_intents row carries part of an unanswered read, which the CHECKs refuse"
                    .to_owned(),
            ));
        }
    };
    Ok(ForgeIntentRecord {
        id: ForgeIntentId {
            attempt_id: super::ulid_from_bytes(&attempt_id)?,
            effect_index,
        },
        stage_id,
        remote,
        branch,
        commit,
        effect,
        recorded_at_ms,
        verdict,
        command_error,
        unanswered,
    })
}

fn attempt_intents_in(
    conn: &rusqlite::Connection,
    attempt_id: Ulid,
) -> KataResult<Vec<ForgeIntentRecord>> {
    let mut statement = conn
        .prepare_cached(&format!(
            "{SELECT_INTENT} WHERE attempt_id = ?1 ORDER BY effect_index"
        ))
        .map_err(storage("prepare an attempt's forge intents"))?;
    let rows = statement
        .query_map(params![attempt_id.to_bytes().as_slice()], read_row)
        .map_err(storage("read an attempt's forge intents"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage("decode an attempt's forge intents"))?;
    rows.into_iter().map(decode_row).collect()
}

/// The intent `id`, as recorded; `Internal` when there is none.
fn intent_in(conn: &rusqlite::Connection, id: ForgeIntentId) -> KataResult<ForgeIntentRecord> {
    let row = conn
        .query_row(
            &format!("{SELECT_INTENT} WHERE attempt_id = ?1 AND effect_index = ?2"),
            params![id.attempt_id.to_bytes().as_slice(), id.effect_index],
            read_row,
        )
        .optional()
        .map_err(storage("read a forge intent"))?
        .ok_or_else(|| KataError::Internal(format!("forge intent {id} is not recorded")))?;
    decode_row(row)
}

/// Write `outcome` on the open intent `id`; `Internal` when there is no such
/// intent or it already has a verdict.
fn settle_in_tx(
    tx: &Transaction<'_>,
    id: ForgeIntentId,
    outcome: &ForgeIntentOutcome,
) -> KataResult<()> {
    let detail = serde_json::to_vec(&outcome.detail)
        .map_err(|error| KataError::Serialization(error.to_string()))?;
    let written = tx
        .execute(
            "UPDATE forge_intents
                SET verdict = ?3, verdict_by = ?4, verdict_json = ?5, verdict_at_ms = ?6
              WHERE attempt_id = ?1 AND effect_index = ?2 AND verdict IS NULL",
            params![
                id.attempt_id.to_bytes().as_slice(),
                id.effect_index,
                outcome.verdict.as_str(),
                outcome.source.as_str(),
                detail,
                super::now_ms(),
            ],
        )
        .map_err(storage("write a forge intent's verdict"))?;
    if written == 1 {
        return Ok(());
    }
    let settled: Option<Option<String>> = tx
        .query_row(
            "SELECT verdict FROM forge_intents WHERE attempt_id = ?1 AND effect_index = ?2",
            params![id.attempt_id.to_bytes().as_slice(), id.effect_index],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage("read a forge intent's verdict"))?;
    Err(KataError::Internal(match settled {
        None => format!("forge intent {id} is not recorded, so it has no verdict to write"),
        Some(verdict) => format!(
            "forge intent {id} already has the verdict `{}`; a verdict is written once",
            verdict.unwrap_or_default()
        ),
    }))
}

/// Refuse while one of `attempt_id`'s intents has no verdict: the attempt's
/// resolution would close a record that still owes its observer's answer.
pub(super) fn refuse_open_forge_intent_in_tx(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
) -> KataResult<()> {
    let open: Option<i64> = tx
        .query_row(
            "SELECT effect_index FROM forge_intents WHERE attempt_id = ?1 AND verdict IS NULL",
            params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage("read an attempt's open forge intent"))?;
    if let Some(effect_index) = open {
        let id = ForgeIntentId {
            attempt_id,
            effect_index,
        };
        return Err(KataError::Internal(format!(
            "workspace_effect attempt {attempt_id} cannot resolve while its forge intent {id} has \
             no verdict"
        )));
    }
    Ok(())
}

impl OperationalDb {
    /// RECORD the intent of the wire effect `intent` announces, immediately
    /// before its first byte. The new intent's index is the attempt's next.
    ///
    /// Answers `None`, writing nothing, unless the attempt is a `pending`
    /// `forge_export` main attempt of an `admitting`/`running` execution.
    ///
    /// # Errors
    ///
    /// `Internal` for an intent recorded while another of the attempt's intents
    /// has no verdict, and a push intent after one of the attempt's pushes was
    /// performed; a store failure.
    pub fn record_forge_intent(
        &self,
        intent: &NewForgeIntent<'_>,
    ) -> KataResult<Option<ForgeIntentRecord>> {
        let attempt_id = intent.attempt_id;
        self.in_writer_txn(|tx| {
            let premise: Option<IntentPremise> = tx
                .query_row(
                    "SELECT a.execution_id, a.stage_id, p.state, el.state, a.assignment_json
                       FROM attempts a
                       LEFT JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                       LEFT JOIN execution_lifecycle el ON el.execution_id = a.execution_id
                      WHERE a.attempt_id = ?1 AND a.executor = 'main'",
                    params![attempt_id.to_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage("read a forge intent's attempt"))?;
            let Some((execution_id, stage_id, state, lifecycle, blob)) = premise else {
                return Ok(None);
            };
            let is_export = super::workspace_effect::workspace_effect_spec(&blob)?
                .is_some_and(|spec| spec.op == WorkspaceEffectOp::ForgeExport);
            let drivable = state.as_deref() == Some(AttemptLifecycle::Pending.as_str())
                && matches!(lifecycle.as_deref(), Some("admitting" | "running"));
            if !is_export || !drivable {
                return Ok(None);
            }
            let prior = attempt_intents_in(tx, attempt_id)?;
            if let Some(open) = prior.iter().find(|recorded| recorded.is_open()) {
                return Err(KataError::Internal(format!(
                    "forge_export attempt {attempt_id} records a new intent while its intent {} \
                     has no verdict",
                    open.id
                )));
            }
            if matches!(intent.effect, ForgeIntentEffect::Push { .. })
                && prior.iter().any(|recorded| {
                    matches!(recorded.effect, ForgeIntentEffect::Push { .. })
                        && recorded.verdict() == Some(ForgeIntentVerdict::Performed)
                })
            {
                return Err(KataError::Internal(format!(
                    "forge_export attempt {attempt_id} records a second push intent after one of \
                     its pushes was performed"
                )));
            }
            let id = ForgeIntentId {
                attempt_id,
                effect_index: prior.last().map_or(0, |last| last.id.effect_index + 1),
            };
            let (lease, base) = match &intent.effect {
                ForgeIntentEffect::Push { lease } => (lease.as_deref(), None),
                ForgeIntentEffect::PullRequest { base } => (None, Some(base.as_str())),
            };
            let recorded_at_ms = super::now_ms();
            tx.execute(
                "INSERT INTO forge_intents
                    (execution_id, attempt_id, stage_id, effect_index, effect, remote, branch,
                     commit_sha, lease, base, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    execution_id,
                    attempt_id.to_bytes().as_slice(),
                    stage_id,
                    id.effect_index,
                    intent.effect.as_str(),
                    intent.remote,
                    intent.branch,
                    intent.commit,
                    lease,
                    base,
                    recorded_at_ms,
                ],
            )
            .map_err(storage("record a forge intent"))?;
            Ok(Some(ForgeIntentRecord {
                id,
                stage_id,
                remote: intent.remote.to_owned(),
                branch: intent.branch.to_owned(),
                commit: intent.commit.to_owned(),
                effect: intent.effect.clone(),
                recorded_at_ms,
                verdict: None,
                command_error: None,
                unanswered: None,
            }))
        })
    }

    /// WRITE the verdict of the open intent `id` — a push's receipt or an
    /// observer's, committed before the export acts on it. It does not ask
    /// whether the attempt is still drivable: a verdict records what the
    /// remote did, whoever settled the attempt since.
    ///
    /// # Errors
    ///
    /// `Internal` when no such intent is recorded or it already has a verdict;
    /// a store failure.
    pub fn settle_forge_intent(
        &self,
        id: ForgeIntentId,
        outcome: &ForgeIntentOutcome,
    ) -> KataResult<()> {
        self.in_writer_txn(|tx| settle_in_tx(tx, id, outcome))
    }

    /// RECORD the error the open intent `id`'s own command returned, before its
    /// observer is asked, and answer the intent as it now stands. Written once:
    /// a NOT PERFORMED verdict on an intent carrying one fails the export rather
    /// than issuing the effect again.
    ///
    /// # Errors
    ///
    /// `Internal` when no such intent is recorded, it already has a verdict or
    /// a command error, or `error` is empty; a store failure.
    pub fn record_forge_command_error(
        &self,
        id: ForgeIntentId,
        error: &str,
    ) -> KataResult<ForgeIntentRecord> {
        self.in_writer_txn(|tx| {
            let written = if error.is_empty() {
                0
            } else {
                tx.execute(
                    "UPDATE forge_intents SET command_error = ?3
                      WHERE attempt_id = ?1 AND effect_index = ?2 AND verdict IS NULL
                        AND command_error IS NULL",
                    params![id.attempt_id.to_bytes().as_slice(), id.effect_index, error],
                )
                .map_err(storage("record a forge intent's command error"))?
            };
            if written != 1 {
                return Err(KataError::Internal(format!(
                    "forge intent {id} is not an open intent without a command error, or the \
                     error is empty, so no command error is written"
                )));
            }
            intent_in(tx, id)
        })
    }

    /// RECORD one read of the open intent `id`'s remote that its observer did not
    /// get answered, failing with `error`, and answer the intent's unanswered
    /// reads, this one counted.
    ///
    /// # Errors
    ///
    /// `Internal` when no such intent is recorded or it already has a verdict;
    /// a store failure.
    pub fn record_unanswered_forge_read(
        &self,
        id: ForgeIntentId,
        error: &str,
    ) -> KataResult<UnansweredReads> {
        self.in_writer_txn(|tx| {
            let written = tx
                .execute(
                    "UPDATE forge_intents
                        SET unanswered_reads = unanswered_reads + 1,
                            last_unanswered_at_ms = ?3, last_read_error = ?4
                      WHERE attempt_id = ?1 AND effect_index = ?2 AND verdict IS NULL",
                    params![
                        id.attempt_id.to_bytes().as_slice(),
                        id.effect_index,
                        super::now_ms(),
                        error,
                    ],
                )
                .map_err(storage("record a forge intent's unanswered read"))?;
            if written != 1 {
                return Err(KataError::Internal(format!(
                    "forge intent {id} is not an open intent, so no unanswered read is recorded"
                )));
            }
            intent_in(tx, id)?.unanswered.ok_or_else(|| {
                KataError::Internal(format!(
                    "forge intent {id} reads back no unanswered read after one was recorded"
                ))
            })
        })
    }

    /// RESOLVE a pending `forge_export` attempt with `resolution`, writing
    /// `settle`'s verdict in the same transaction — the pull request's receipt
    /// commits with the export's result, and an observer's `Unclassified` with
    /// the failure it records. Answers `None` when the `pending` premise
    /// lapsed.
    ///
    /// # Errors
    ///
    /// `Internal` when one of the attempt's intents still has no verdict once
    /// `settle` is written, and for a `settle` the write-once verdict refuses;
    /// the main resolution's refusals (an execution whose outcome is
    /// published); a store failure. Every refusal writes nothing, the verdict
    /// included.
    pub fn resolve_forge_export_attempt(
        &self,
        attempt_id: Ulid,
        settle: Option<(ForgeIntentId, &ForgeIntentOutcome)>,
        resolution: &MainResolution<'_>,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for resolve_forge_export_attempt"
                ))
            })?;
        let payload = self.prepare_main_resolution(execution_id, resolution)?;
        self.in_writer_txn(|tx| {
            if let Some((id, outcome)) = settle {
                settle_in_tx(tx, id, outcome)?;
            }
            refuse_open_forge_intent_in_tx(tx, attempt_id)?;
            Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )
        })
    }

    /// `attempt_id`'s intents, in effect order.
    ///
    /// # Errors
    ///
    /// A store failure or a row outside the stamped shape.
    pub fn forge_intents(&self, attempt_id: Ulid) -> KataResult<Vec<ForgeIntentRecord>> {
        self.with_read(|conn| attempt_intents_in(conn, attempt_id))
    }

    /// The commit of the last push to `remote`'s `branch` that one of
    /// `execution_id`'s intents records as performed — the head kata itself
    /// last wrote there, which a later export of the same execution may lease
    /// on.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn last_performed_forge_push(
        &self,
        execution_id: Ulid,
        remote: &str,
        branch: &str,
    ) -> KataResult<Option<String>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT commit_sha FROM forge_intents
                  WHERE execution_id = ?1 AND effect = 'push' AND remote = ?2 AND branch = ?3
                    AND verdict = 'performed'
                  ORDER BY seq DESC LIMIT 1",
                params![execution_id.to_bytes().as_slice(), remote, branch],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("read the last performed forge push"))
        })
    }
}
