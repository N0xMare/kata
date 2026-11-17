//! The ADAPTER QUALIFICATION MATRIX: every (adapter, requirement)
//! cell, classified three ways, with no cell left unwritten.
//!
//! # Why a matrix and not a list of passing tests
//!
//! ADR-0001 admits one agent contract, the embedded nanocode harness (two
//! kinds, one per model provider), and requires that each adapter "declares
//! what its protocol offers, measured, in its module doc and in the adapter
//! qualification matrix, and refuses by name a request it cannot serve". This
//! matrix is where each adapter's answer is declared, requirement by requirement.
//! A requirement a protocol cannot meet is not a cell: it is left out of
//! [`Requirement`], and the module doc says why. A list of green tests
//! answers *what has been proved*; it cannot answer *what has not been asked*,
//! and the second question is the one a qualification claim rests on. Each
//! kind's column is spelled out per requirement by its own exhaustive
//! `*_coverage` function. The two nanocode kinds' adapter lives in
//! `kata-agent-nanocode`, so their columns cite that crate's tests, read by path
//! (`kata-agent` never builds nanocode), and their real-binary row cites
//! kata-worker's `nanocode_capsule_live`, the adapter against the real
//! `kata-toolhost` in a real capsule. Like every kind's, their columns carry no
//! `NotRun` cell and exactly one real-binary row.
//!
//! One requirement of theirs is proved on a configuration no kata worker runs:
//! `CancellationUnacknowledged`. A cancel nanocode does not confirm arises
//! only on the vendored engine's own thread backend, where a cell inside one
//! long native step holds its thread past the interrupt; behind kata's Code
//! Mode backend, which every worker installs, the cancel's terminate kills the
//! step's interpreter process and nanocode confirms it. So both columns' rows
//! cite `kata-agent-nanocode`'s `nanocode_thread_backend` cells, which install
//! no limits: they pin the adapter's classification of an unconfirmed stop
//! (ambiguous at the crossed class, never `Cancelled`), the same code on both
//! backends, and no production trigger of it is measured.
//!
//! The requirements are the embedded harness's, in its own vocabulary: a
//! toolhost wire to the capsule and a model provider. It makes no inbound
//! callback (every tool the model calls reaches the capsule as a toolhost
//! frame) and runs one session per turn in process, so no requirement asks it
//! to serve a filesystem or terminal callback or to ignore another client's
//! turn frame: neither can arise.
//!
//! # The two compile-time properties, stated exactly
//!
//! 1. **A new [`AdapterKind`] fails to compile until it is classified.**
//!    [`coverage`] matches on the kind with no wildcard arm, and each arm is a
//!    `*_coverage` function exhaustive over [`Requirement`], like
//!    [`nanocode_openai_coverage`].
//! 2. **A new [`Requirement`] fails to compile until each adapter classifies
//!    it.** Every `*_coverage` function matches on the requirement with no
//!    wildcard arm, and [`Requirement::ALL`] is the fold basis the tests sweep.
//!
//! # Three values, and why two would not do
//!
//! * [`Coverage::Test`] — a named test proves it, at a named [`Tier`].
//! * [`Coverage::NotRun`] — nobody has asked. A gap, and it says so.
//!
//! The third value is the [`Tier`] on `Test`: a hermetic row runs on every host,
//! and a real-binary row runs wherever the containment lane runs: the
//! nanocode kinds' capsule-side binary is the toolhost this tree builds
//! ([`Tier::RealBinary`]). A matrix that
//! did not distinguish them would let a claim that holds on one box read as a
//! claim that holds everywhere.

use std::collections::BTreeSet;
use std::path::PathBuf;

use kata_types::agent::AdapterKind;

/// One named behavior an adapter must be qualified for: a claim about what kata's
/// adapter has been OBSERVED to do, not about what the harness offers.
/// `Cancellation` appears here because a harness that can cancel a turn and an
/// adapter that never asks it to are different facts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Requirement {
    /// The toolhost's handshake is checked (its `Hello` and source digest)
    /// before any model request.
    Handshake,
    /// A completed turn returns the model's own final message.
    NormalResult,
    /// A cancel reaches the harness as its own turn cancel, and a cancel it
    /// acknowledged is reported as a cancel.
    Cancellation,
    /// A cancel the harness did not acknowledge is not reported as a cancel.
    CancellationUnacknowledged,
    /// Reported usage reaches the metering classifier undivided.
    UsageReported,
    /// Unreported or unparseable usage stays unavailable and never becomes zero.
    UsageUnknown,
    /// The harness probes nothing on the host: the execution environment it
    /// reads is the capsule's, supplied by kata.
    NoHostProbe,
    /// A re-dispatched attempt re-derives the same session id from its seed, and
    /// the session opened for it is the one driven.
    RedispatchRederivesSessionId,
    /// A protocol disconnect after the issuance watermark is ambiguous and
    /// latches.
    DisconnectAfterIssuance,
    /// The watermark is crossed before a model request leaves the harness,
    /// before any byte of its answer comes back — trust boundary 6's *after
    /// possible issuance* read as an ordering against the request rather than
    /// against the reply.
    WatermarkPrecedesTheWrite,
    /// A provider that REFUSES the turn's first request ends the turn, rather
    /// than leaving the caller waiting for an answer that will never come.
    RefusedTurnStart,
    /// A cancel the harness announced that kata never asked for is not
    /// reported as a confirmed cancel.
    UnaskedInterruptionIsNotACancel,
    /// Per-turn state does not leak from one prompt into the next on one session.
    PerTurnStateIsReset,
    /// A toolhost that ignores `Shutdown` cannot hang `close()`: `close`
    /// escalates to `SIGKILL`.
    CloseEscalatesPastShutdown,
    /// A turn the provider failed carries the provider's own reason.
    FailedTurnCarriesItsReason,
    /// A toolhost frame the codec refuses is named in the outcome.
    ParseFailureNamed,
    /// The turn's end leaves no capsule process behind, and says so.
    RestartCleanup,
    /// One toolhost per session, and a scope the adapter cannot serve is
    /// refused at `open`, before the wire.
    BoundedOwnership,
    /// The adapter handshakes with the REAL `kata-toolhost` in a real capsule.
    RealBinaryHandshake,
}

impl Requirement {
    /// Every requirement. The fold basis for the sweeps below, so another
    /// cannot be added without appearing in every table this file prints.
    pub const ALL: [Self; 19] = [
        Self::Handshake,
        Self::NormalResult,
        Self::Cancellation,
        Self::CancellationUnacknowledged,
        Self::UsageReported,
        Self::UsageUnknown,
        Self::NoHostProbe,
        Self::RedispatchRederivesSessionId,
        Self::DisconnectAfterIssuance,
        Self::WatermarkPrecedesTheWrite,
        Self::RefusedTurnStart,
        Self::UnaskedInterruptionIsNotACancel,
        Self::PerTurnStateIsReset,
        Self::CloseEscalatesPastShutdown,
        Self::FailedTurnCarriesItsReason,
        Self::ParseFailureNamed,
        Self::RestartCleanup,
        Self::BoundedOwnership,
        Self::RealBinaryHandshake,
    ];

    /// Stable snake_case label for the printed table.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::NormalResult => "normal_result",
            Self::Cancellation => "cancellation",
            Self::CancellationUnacknowledged => "cancellation_unacknowledged",
            Self::UsageReported => "usage_reported",
            Self::UsageUnknown => "usage_unknown",
            Self::NoHostProbe => "no_host_probe",
            Self::RedispatchRederivesSessionId => "redispatch_rederives_session_id",
            Self::DisconnectAfterIssuance => "disconnect_after_issuance",
            Self::WatermarkPrecedesTheWrite => "watermark_precedes_the_write",
            Self::RefusedTurnStart => "refused_turn_start",
            Self::UnaskedInterruptionIsNotACancel => "unasked_interruption_is_not_a_cancel",
            Self::PerTurnStateIsReset => "per_turn_state_is_reset",
            Self::CloseEscalatesPastShutdown => "close_escalates_past_shutdown",
            Self::FailedTurnCarriesItsReason => "failed_turn_carries_its_reason",
            Self::ParseFailureNamed => "parse_failure_named",
            Self::RestartCleanup => "restart_cleanup",
            Self::BoundedOwnership => "bounded_ownership",
            Self::RealBinaryHandshake => "real_binary_handshake",
        }
    }
}

/// Where a proving test runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Runs on every host: a mock model provider and a toolhost double,
    /// nothing installed.
    Hermetic,
    /// Runs the `kata-toolhost` this tree builds in a real rootless capsule: a
    /// live cell the containment lane runs, which fails rather than skips on a
    /// host that cannot run it.
    RealBinary,
}

impl Tier {
    #[must_use]
    const fn as_label(self) -> &'static str {
        match self {
            Self::Hermetic => "hermetic",
            Self::RealBinary => "real-binary",
        }
    }
}

/// One cell.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Coverage {
    /// Proved by this test, at this tier.
    Test(&'static str, Tier),
    /// Not asked. The reason says who owes it.
    NotRun(&'static str),
}

/// The whole matrix.
///
/// # Errors in classification are compile errors
///
/// No wildcard arm. A new [`AdapterKind`] does not compile until somebody
/// writes its own `*_coverage` column.
#[must_use]
pub fn coverage(kind: AdapterKind, requirement: Requirement) -> Coverage {
    match kind {
        AdapterKind::NanocodeOpenai => nanocode_openai_coverage(requirement),
        AdapterKind::NanocodeAnthropic => nanocode_anthropic_coverage(requirement),
    }
}

/// The `nanocode_openai` column: `kata-agent-nanocode`'s `nanocode_qualification`
/// cells against a mock Responses provider and a toolhost double (and, for
/// `CancellationUnacknowledged`, its `nanocode_thread_backend` cells), and its
/// in-crate unit cells.
///
/// # Errors in classification are compile errors
///
/// No wildcard arm.
#[must_use]
pub const fn nanocode_openai_coverage(requirement: Requirement) -> Coverage {
    match requirement {
        Requirement::Handshake => Coverage::Test(
            "a_toolhost_with_another_source_digest_is_refused_before_any_model_call",
            Tier::Hermetic,
        ),
        Requirement::NormalResult => {
            Coverage::Test("a_completed_turn_returns_the_final_message", Tier::Hermetic)
        }
        Requirement::Cancellation => {
            Coverage::Test("a_confirmed_cancel_carries_partial_usage", Tier::Hermetic)
        }
        // On the engine's thread backend (`nanocode_thread_backend`, no
        // limits installed), the one configuration where nanocode leaves a
        // cancel unconfirmed: behind kata's backend the same cancel is
        // confirmed (module doc).
        Requirement::CancellationUnacknowledged => Coverage::Test(
            "an_unconfirmed_cancel_is_ambiguous_at_the_crossed_class",
            Tier::Hermetic,
        ),
        Requirement::UsageReported => Coverage::Test(
            "usage_is_summed_per_model_call_with_cached_tokens_split_out",
            Tier::Hermetic,
        ),
        // A call reporting no usage leaves the turn's usage unknown. Residual,
        // MEASURED at 2ac77424 and the same on the Messages kind: a usage
        // object that is present but omits a class reads that class as 0
        // (nanocode's parser defaults every class), so kata cannot tell an
        // omitted class from a stated zero. The row covers an absent usage
        // only.
        Requirement::UsageUnknown => Coverage::Test(
            "a_call_reporting_no_usage_leaves_the_usage_unknown",
            Tier::Hermetic,
        ),
        Requirement::NoHostProbe => Coverage::Test(
            "no_host_probe_without_a_supplied_environment",
            Tier::Hermetic,
        ),
        Requirement::RedispatchRederivesSessionId => {
            Coverage::Test("the_session_id_is_rederived_from_the_seed", Tier::Hermetic)
        }
        // The harness's protocol is the toolhost wire: its break after a
        // forwarded tool frame latches and is ambiguous. The MODEL
        // connection's drop is the provider's failure, classified from
        // nanocode's typed error (`TurnOutcome::ProviderFailed`).
        Requirement::DisconnectAfterIssuance => Coverage::Test(
            "a_toolhost_eof_mid_turn_cancels_the_turn_and_is_ambiguous",
            Tier::Hermetic,
        ),
        Requirement::WatermarkPrecedesTheWrite => Coverage::Test(
            "the_first_generation_attempt_marks_model_tokens",
            Tier::Hermetic,
        ),
        Requirement::UnaskedInterruptionIsNotACancel => {
            Coverage::Test("an_unasked_turn_cancelled_is_ambiguous", Tier::Hermetic)
        }
        Requirement::PerTurnStateIsReset => {
            Coverage::Test("a_second_prompt_on_one_session_is_refused", Tier::Hermetic)
        }
        Requirement::CloseEscalatesPastShutdown => {
            Coverage::Test("close_escalates_past_a_swallowed_shutdown", Tier::Hermetic)
        }
        // One cell proves both: the provider's refusal of the first request
        // ends the turn, and the outcome carries the provider's own reason.
        Requirement::RefusedTurnStart | Requirement::FailedTurnCarriesItsReason => Coverage::Test(
            "a_provider_refusal_fails_the_turn_with_the_providers_reason",
            Tier::Hermetic,
        ),
        Requirement::ParseFailureNamed => Coverage::Test(
            "a_toolhost_frame_the_codec_refuses_is_named_in_the_outcome",
            Tier::Hermetic,
        ),
        Requirement::RestartCleanup => Coverage::Test(
            "every_turn_end_kills_the_capsules_processes_before_the_outcome",
            Tier::Hermetic,
        ),
        Requirement::BoundedOwnership => {
            Coverage::Test("a_scope_without_work_is_refused_at_open", Tier::Hermetic)
        }
        // nanocode has no vendor binary: its loop is linked into the worker, and the
        // one vendor-side binary a turn meets is `kata-toolhost`, the capsule's init.
        // So the real-binary row is the real adapter handshaking with the real
        // toolhost in a real rootless capsule, its model a mock provider: no model
        // budget. A real provider's turn is a maintainer's funded live acceptance,
        // not this row.
        Requirement::RealBinaryHandshake => Coverage::Test(
            "a_nanocode_openai_turn_admits_the_real_toolhost_before_its_first_model_request",
            Tier::RealBinary,
        ),
    }
}

/// The `nanocode_anthropic` column: `kata-agent-nanocode`'s
/// `nanocode_qualification` cells against the mock Messages endpoint and the
/// toolhost double (and, for `CancellationUnacknowledged`, its
/// `nanocode_thread_backend` cells), and its in-crate unit cells. A row the session decides the
/// same way on either kind (the handshake, the turn's end, `close`, `open`'s
/// scope check, the codec latch, the one-turn rule, the host-probe check)
/// cites the cell the OpenAI column cites, which runs once per kind; an
/// unasked interruption is classified by the one `classify_error` both kinds'
/// outcomes go through, so its unit cell serves both columns.
///
/// # Errors in classification are compile errors
///
/// No wildcard arm.
#[must_use]
pub const fn nanocode_anthropic_coverage(requirement: Requirement) -> Coverage {
    match requirement {
        Requirement::Handshake => Coverage::Test(
            "a_toolhost_with_another_source_digest_is_refused_before_any_model_call",
            Tier::Hermetic,
        ),
        Requirement::NormalResult => Coverage::Test(
            "an_anthropic_turn_returns_the_final_message",
            Tier::Hermetic,
        ),
        Requirement::Cancellation => Coverage::Test(
            "an_anthropic_confirmed_cancel_carries_partial_usage",
            Tier::Hermetic,
        ),
        // On the engine's thread backend, as the OpenAI column's row
        // (module doc).
        Requirement::CancellationUnacknowledged => Coverage::Test(
            "an_anthropic_cancel_nanocode_does_not_confirm_is_ambiguous",
            Tier::Hermetic,
        ),
        Requirement::UsageReported => Coverage::Test(
            "an_anthropic_turns_usage_is_summed_per_model_call",
            Tier::Hermetic,
        ),
        // The Messages API states usage on every response, and a response
        // without it does not parse: the call fails and is never metered.
        // Residual, MEASURED at 2ac77424 and the same on the Responses kind: a
        // usage object that is present but omits a class reads that class as
        // 0 (nanocode's parser defaults every class), so kata cannot tell an
        // omitted class from a stated zero. The row covers an absent usage
        // only.
        Requirement::UsageUnknown => Coverage::Test(
            "an_anthropic_call_stating_no_usage_is_never_metered",
            Tier::Hermetic,
        ),
        Requirement::NoHostProbe => Coverage::Test(
            "no_host_probe_without_a_supplied_environment",
            Tier::Hermetic,
        ),
        // The Messages wire carries no session id (measured), so the session
        // driven is read off nanocode's own telemetry: every `agent.turn` and
        // `model.call` span names the session's id, and no request line,
        // header or body the provider received names it.
        Requirement::RedispatchRederivesSessionId => Coverage::Test(
            "the_anthropic_session_id_is_rederived_from_the_seed",
            Tier::Hermetic,
        ),
        Requirement::WatermarkPrecedesTheWrite => Coverage::Test(
            "the_first_messages_request_marks_model_tokens",
            Tier::Hermetic,
        ),
        // A unit cell over `classify_error`, as on the OpenAI column, and it
        // runs no turn: kata never drives a turn into the arm. The session
        // asks nanocode to cancel only in `stop_turn`, after recording the
        // token or latch stop it serves (the `CancelToken` is the contract's
        // one cancel verb). Only a `TurnCancelled` nanocode raised on its own
        // reaches the arm.
        Requirement::UnaskedInterruptionIsNotACancel => {
            Coverage::Test("an_unasked_turn_cancelled_is_ambiguous", Tier::Hermetic)
        }
        Requirement::PerTurnStateIsReset => {
            Coverage::Test("a_second_prompt_on_one_session_is_refused", Tier::Hermetic)
        }
        Requirement::CloseEscalatesPastShutdown => {
            Coverage::Test("close_escalates_past_a_swallowed_shutdown", Tier::Hermetic)
        }
        // One cell proves both, as on the OpenAI column: it runs both kinds.
        Requirement::RefusedTurnStart | Requirement::FailedTurnCarriesItsReason => Coverage::Test(
            "a_provider_refusal_fails_the_turn_with_the_providers_reason",
            Tier::Hermetic,
        ),
        // One cell proves both on the Anthropic kind: the parametrised cell
        // breaks the toolhost wire (the harness's protocol) after the forwarded
        // `exec`, latching it, and names the codec's refusal; the turn is
        // ambiguous. The MODEL connection's drop is the provider's failure,
        // classified from nanocode's typed error.
        Requirement::DisconnectAfterIssuance | Requirement::ParseFailureNamed => Coverage::Test(
            "a_toolhost_frame_the_codec_refuses_is_named_in_the_outcome",
            Tier::Hermetic,
        ),
        Requirement::RestartCleanup => Coverage::Test(
            "every_turn_end_kills_the_capsules_processes_before_the_outcome",
            Tier::Hermetic,
        ),
        Requirement::BoundedOwnership => {
            Coverage::Test("a_scope_without_work_is_refused_at_open", Tier::Hermetic)
        }
        // As the OpenAI column's: the real toolhost in a real capsule, a mock model.
        Requirement::RealBinaryHandshake => Coverage::Test(
            "a_nanocode_anthropic_turn_admits_the_real_toolhost_before_its_first_model_request",
            Tier::RealBinary,
        ),
    }
}

// ── the checks ---------------------------------------------------------------

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Where `kind`'s proving tests live: `kata-agent-nanocode`'s `tests/` and its
/// `src/` (whose in-crate unit cells prove the classification rows), and the one
/// kata-worker live binary that runs the adapter against the real toolhost in a
/// real capsule, read by path.
fn proving_dirs(kind: AdapterKind) -> Vec<PathBuf> {
    match kind {
        AdapterKind::NanocodeOpenai | AdapterKind::NanocodeAnthropic => {
            let nanocode = crate_root().join("../agent-nanocode");
            vec![
                nanocode.join("tests"),
                nanocode.join("src"),
                crate_root().join("../worker/tests/nanocode_capsule_live.rs"),
            ]
        }
    }
}

/// Every `fn NAME(` defined in a `*.rs` under `dirs` (a directory, recursively, or
/// one file).
///
/// Read off the filesystem rather than `include_str!`ed, so a proving test may
/// live in ANY of the crate's test binaries and a row is not silently satisfied
/// by a name that happens to appear in a doc comment (the scan looks for a `fn`
/// definition, not for the bare string).
fn test_function_names(dirs: &[PathBuf]) -> BTreeSet<String> {
    fn walk(dir: &std::path::Path, names: &mut BTreeSet<String>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, names);
                continue;
            }
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            collect_function_names(&source, names);
        }
    }
    let mut names = BTreeSet::new();
    for dir in dirs {
        if dir.is_file() {
            let source = std::fs::read_to_string(dir)
                .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()));
            collect_function_names(&source, &mut names);
        } else {
            walk(dir, &mut names);
        }
    }
    names
}

/// The pure core of the scan, so the counterfactual can run on synthetic input.
fn collect_function_names(source: &str, into: &mut BTreeSet<String>) {
    for line in source.lines() {
        let trimmed = line.trim_start();
        // A DEFINITION starts the line (after indentation), so `//! see fn foo()`
        // in a doc paragraph does not count.
        let Some(rest) = trimmed
            .strip_prefix("fn ")
            .or_else(|| trimmed.strip_prefix("async fn "))
            .or_else(|| trimmed.strip_prefix("pub fn "))
            .or_else(|| trimmed.strip_prefix("pub async fn "))
        else {
            continue;
        };
        if let Some(name) = rest.split(['(', '<']).next()
            && !name.is_empty()
        {
            into.insert(name.to_string());
        }
    }
}

/// **Every cell is classified, and the matrix is total.**
#[test]
fn every_cell_of_the_matrix_is_classified() {
    let mut cells = 0_usize;
    for kind in AdapterKind::ALL {
        for requirement in Requirement::ALL {
            let cell = coverage(kind, requirement);
            match &cell {
                Coverage::Test(name, _) => assert!(
                    !name.is_empty(),
                    "{}/{} names an empty test",
                    kind.as_label(),
                    requirement.as_label()
                ),
                Coverage::NotRun(reason) => assert!(
                    reason.len() > 40,
                    "{}/{} states a reason too short to be one: {reason:?}",
                    kind.as_label(),
                    requirement.as_label()
                ),
            }
            cells += 1;
        }
    }
    assert_eq!(
        cells,
        AdapterKind::ALL.len() * Requirement::ALL.len(),
        "the sweep must visit every cell"
    );
}

/// **Every test the matrix names EXISTS, where its kind's adapter is proved.**
///
/// A matrix that cites a renamed or deleted test is worse than one with a gap: it
/// reads as a decision somebody made about code that runs. This is the
/// `#[kata_timeout]`-was-decorative failure shape applied to a coverage claim.
#[test]
fn every_named_test_exists_where_its_kind_is_proved() {
    for kind in AdapterKind::ALL {
        let dirs = proving_dirs(kind);
        let defined = test_function_names(&dirs);
        for requirement in Requirement::ALL {
            if let Coverage::Test(name, _) = coverage(kind, requirement) {
                assert!(
                    defined.contains(name),
                    "the matrix says `{}`/`{}` is proved by `{name}`, and no test by that name is \
                     defined under {dirs:?}",
                    kind.as_label(),
                    requirement.as_label()
                );
            }
        }
    }
}

/// **The scan finds a definition and not a mention.**
///
/// The counterfactual for the check above, on synthetic input, because a coverage
/// rule that cannot tell a `fn` from a sentence about one would pass for a matrix
/// citing tests nobody wrote.
#[test]
fn the_name_scan_finds_definitions_and_not_mentions() {
    let mut found = BTreeSet::new();
    collect_function_names(
        "//! see fn not_a_definition() for details\n\
         /// and fn also_not_one()\n\
         fn a_real_one() {}\n\
         async fn an_async_one(argument: u8) {}\n\
         pub fn a_public_one<T>() {}\n",
        &mut found,
    );
    assert_eq!(
        found.iter().map(String::as_str).collect::<Vec<&str>>(),
        ["a_public_one", "a_real_one", "an_async_one"],
        "a mention inside a comment must not satisfy a coverage row"
    );
}

/// **Every kind's column is total.** No requirement is unasked, and exactly one
/// is proved against the real toolhost binary: every kind runs as a capsule, so
/// none may carry a `NotRun` gap.
#[test]
fn every_adapter_column_is_total() {
    for kind in AdapterKind::ALL {
        let column: Vec<Coverage> = Requirement::ALL
            .into_iter()
            .map(|requirement| coverage(kind, requirement))
            .collect();
        let real_binary = column
            .iter()
            .filter(|cell| matches!(cell, Coverage::Test(_, Tier::RealBinary)))
            .count();
        assert!(
            !column
                .iter()
                .any(|cell| matches!(cell, Coverage::NotRun(_))),
            "an adapter must have no unasked requirement: {kind:?} -> {column:?}"
        );
        assert_eq!(
            real_binary,
            1,
            "{}: exactly one requirement is proved against the real binary",
            kind.as_label()
        );
    }
}

/// **The table, printed.**
///
/// Not decoration: the four-valued rendering is the artefact a reader of a
/// qualification claim actually wants, and printing it from the same function the
/// assertions read means the two cannot drift. Run it with
/// `cargo nextest run -p kata-agent -E 'binary(qualification_matrix)' --no-capture`.
#[test]
fn print_the_qualification_matrix() {
    let width = Requirement::ALL
        .into_iter()
        .map(|requirement| requirement.as_label().len())
        .max()
        .unwrap_or(0);
    println!(
        "\nagent adapter qualification matrix\n\
         legend: TEST <name> [tier] | NOT-RUN\n"
    );
    for kind in AdapterKind::ALL {
        println!("{}:", kind.as_label());
        for requirement in Requirement::ALL {
            let cell = match coverage(kind, requirement) {
                Coverage::Test(name, tier) => {
                    format!("TEST        {name} [{}]", tier.as_label())
                }
                Coverage::NotRun(_) => "NOT-RUN".to_string(),
            };
            println!("  {:<width$}  {cell}", requirement.as_label());
        }
        println!();
    }
    let counts = |predicate: fn(&Coverage) -> bool| {
        AdapterKind::ALL
            .into_iter()
            .flat_map(|kind| Requirement::ALL.into_iter().map(move |r| coverage(kind, r)))
            .filter(predicate)
            .count()
    };
    println!(
        "totals: {} test, {} not-run, of {} cells",
        counts(|cell| matches!(cell, Coverage::Test(..))),
        counts(|cell| matches!(cell, Coverage::NotRun(_))),
        AdapterKind::ALL.len() * Requirement::ALL.len(),
    );
    // A print-only test still has to fail when the thing it prints is empty.
    assert!(
        !Requirement::ALL.is_empty() && !AdapterKind::ALL.is_empty(),
        "an empty matrix prints nothing and proves nothing"
    );
}
