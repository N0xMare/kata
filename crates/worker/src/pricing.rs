//! Static `(BillingBackend, model) → USD/token` pricing table.
//!
//! # Unit: micro-USD
//!
//! A metered cost is carried as integer micro-USD (USD × 10⁶), so sub-cent
//! precision is preserved across long workflow runs; a reader recovers USD by
//! dividing by 1_000_000.
//!
//! # Runtime-reloadable pricing
//!
//! [`PRICE_TABLE`] remains the built-in fallback/default, but operators
//! can override any `(backend, model)` row from the SAME `kata.toml`
//! [`kata_core::config_manager::ConfigManager`] already loads the rest
//! of `KataConfig` from — no second config path. The row schema is
//! `KataConfig`'s own [`PricingConfig`]: the closed `kata.toml` parse admits
//! `[pricing]` and refuses a misspelled row key at load, and
//! [`load_overrides_from_snapshot`] reads ONLY `[pricing]` out of the same
//! validated bytes with that same type. Declare overrides like:
//!
//! ```toml
//! [[pricing.models]]
//! backend = "anthropic"
//! model = "claude-sonnet-5-5"
//! input_rate_per_mtok = 2.00
//! output_rate_per_mtok = 10.00
//! cache_read_multiplier = 0.05   # required
//! cache_write_multiplier = 1.25  # required
//! ```
//!
//! A turn's prompt-cache reads and writes are their own classes (each priced
//! adapter splits them out of the input its provider states), so a row bills
//! each through its own multiplier alone, and both fields are REQUIRED — a row
//! that omits either is refused at load rather than billing that class nothing.
//! On the row above `0.05` charges a cached read at a twentieth of the input
//! rate and `1.25` a 5-minute cache write at 1.25× it, as Anthropic bills them
//! and as the built-in row does.
//!
//! The installed main calls [`load_overrides_from_snapshot`] with the
//! exact bytes and digest already accepted by `ConfigManager`; they never reopen
//! the path during startup. Pricing changes are restart-required like every
//! other non-telemetry field. Absent that call, [`lookup_cost_usd`] /
//! [`cache_read_savings_usd`] price from the built-in `PRICE_TABLE` only.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use kata_types::agent::BillingBackend;
use kata_types::cache::TokenUsage;
use kata_types::config::{PriceOverride, PricingConfig};
use kata_types::error::{KataError, KataResult};
use kata_types::metering::{EstimateBasis, MeteredCost, ProviderCost};

/// The `YYYY-MM` the shipped [`PRICE_TABLE`] list prices were captured: the
/// Anthropic rows, read off Anthropic's official pricing page,
/// <https://platform.claude.com/docs/en/about-claude/pricing> (fetched
/// 2026-11-02; `docs.anthropic.com/en/docs/about-claude/pricing` redirects
/// there), and the model ids off
/// <https://platform.claude.com/docs/en/about-claude/models/overview> (same
/// fetch).
///
/// # Why this is a constant and not a comment
///
/// Every [`MeteredCost::Estimated`] figure derived from a built-in row carries
/// this date in its [`EstimateBasis::PriceTable`], so an operator reading an
/// `ExecutionRecord` can see how old the arithmetic behind a cost is. A bound
/// evaluated against months-old prices trips early or late, and a table age
/// recorded only in prose would be invisible to every surface, and therefore
/// unable to qualify a single number.
///
/// Bump this in the SAME commit that revises a rate. [`PRICE_TABLE_STALE_AFTER_MONTHS`]
/// turns a forgotten bump into a warning rather than silence.
pub const PRICE_TABLE_AS_OF: &str = "2026-11";

/// How old [`PRICE_TABLE_AS_OF`] may get before an estimate derived from it
/// warns.
///
/// A quarter: providers revise list prices on roughly that cadence, so a table
/// older than one is likelier wrong than right. Deliberately short enough that
/// the mechanism is LIVE rather than dormant — a threshold no shipped state can
/// reach is a check satisfiable by observing nothing.
pub const PRICE_TABLE_STALE_AFTER_MONTHS: u32 = 3;

/// Whole months between [`PRICE_TABLE_AS_OF`] and `now`, saturating at 0 for a
/// `now` that precedes the table (a clock skew must not read as "fresh by a
/// negative amount", nor panic).
///
/// Pure and total so the staleness rule can be tested at fixed dates instead of
/// against the wall clock — a test that only passes on some days is a test that
/// measures the calendar.
#[must_use]
pub fn price_table_age_months(now: chrono::DateTime<chrono::Utc>) -> u32 {
    months_since(PRICE_TABLE_AS_OF, now)
}

/// Whole months between the `YYYY-MM` `as_of` and `now` — [`price_table_age_months`]
/// for any row date.
fn months_since(as_of: &str, now: chrono::DateTime<chrono::Utc>) -> u32 {
    use chrono::Datelike;
    let Some((table_year, table_month)) = parse_year_month(as_of) else {
        return 0;
    };
    let now_months = i64::from(now.year()) * 12 + i64::from(now.month());
    let table_months = i64::from(table_year) * 12 + i64::from(table_month);
    u32::try_from(now_months.saturating_sub(table_months).max(0)).unwrap_or(u32::MAX)
}

/// Split a `YYYY-MM` string. `None` for any other shape — the caller then
/// treats the table as age 0 rather than guessing.
fn parse_year_month(s: &str) -> Option<(i32, u32)> {
    let (year, month) = s.split_once('-')?;
    Some((year.parse().ok()?, month.parse().ok()?))
}

/// Pricing rows: `(backend, model_name, input_$/M, output_$/M, cache_read_multiplier,
/// cache_write_multiplier, as_of)`.
///
/// Model name strings must match exactly what operators configure in
/// `[agents.<name>] model = "..."` (or the CLI default). Case-sensitive.
///
/// The table holds a row only for a backend a turn can bill against —
/// [`kata_types::agent::AdapterKind::billing_backend`] maps a
/// `nanocode_anthropic` turn to `anthropic` — and an operator
/// `[[pricing.models]]` row prices any other model such a turn names.
///
/// A `nanocode_openai` turn bills against no backend until OpenAI rows are
/// verified against OpenAI's published prices (the source of each named in the
/// commit) and a billing key for them is added and mapped in `billing_backend`,
/// in the same commit.
///
/// Update this table when providers revise pricing, and bump
/// [`PRICE_TABLE_AS_OF`] in the same commit — it is what every estimate reports
/// as its own provenance.
///
/// # Cache-aware pricing
///
/// `cache_read_multiplier` and `cache_write_multiplier` are the factors applied
/// to `input_rate` when pricing tokens served from, and written into, the
/// provider's prompt cache. The adapter reports `input` EXCLUSIVE of both, so
/// `input_cost + cache_read_cost + cache_write_cost` counts each token once.
///
/// # The Anthropic rows
///
/// Anthropic's list prices per MTok, as of [`PRICE_TABLE_AS_OF`] (source and
/// fetch date there), for the Claude 5 ids a `nanocode_anthropic` turn can pin
/// (nanocode's `ClaudeModel`, 8ec3b215) that the page prices at a flat rate.
/// Cache reads are 0.025× input on Fable 5.1 and Mythos 5.1, 0.05× on Opus 5.5
/// and Sonnet 5.5 (the page's footnotes); a cache WRITE is priced at the 5-minute write
/// rate, 1.25× input, because that is the only write a priced turn makes: nanocode
/// requests a one-hour TTL only when `cache_one_hour` is set (its builder's, or a
/// restored session's), or, on a SUBSCRIPTION session, once a request follows the
/// last by over five minutes (its `cache_ttl` and `outlived_cache`, 8ec3b215) —
/// kata sets neither, and a subscription turn is never priced. Long context is billed at these standard
/// rates on every row here (Anthropic: "Claude 4.6 and later models (except
/// Claude Haiku 5.5) include the full 1M token context window at standard
/// pricing").
///
/// `claude-mythos-5-1` is the id nanocode pins for the page's "Claude Mythos 5.1"
/// (limited availability); the models page lists no id for it.
///
/// Left out, each by its reason, so a turn on it is estimated at the
/// unknown-model floor (an upper bound, `$15`/`$75` per MTok, above every
/// Claude 5 price) rather than at a rate kata cannot stand behind:
/// `claude-haiku-5-5` is priced by each REQUEST's prompt length (over 100,000
/// tokens it pays the higher tier) and a turn's summed usage cannot say which
/// requests crossed; `claude-fable-5-5`, which nanocode names, is on neither of
/// Anthropic's pages; the legacy `claude-opus-5`, `claude-sonnet-5` and
/// `claude-fable-5` are ids nanocode refuses, so no priced adapter runs them;
/// `claude-fable-5-2` and `claude-mythos-5-2`, which nanocode names since
/// 8ec3b215, have no price fetched for them yet.
/// Not modelled: the 1.1× US `inference_geo`
/// multiplier and fast mode, neither of which kata or nanocode requests, and the
/// Batch API, which an agent turn never uses.
static PRICE_TABLE: &[(BillingBackend, &str, f64, f64, f64, f64, &str)] = &[
    // ── Anthropic: input, output, cache read ×, 5-minute cache write × ──
    (
        BillingBackend::Anthropic,
        "claude-fable-5-1",
        10.0,
        50.0,
        0.025,
        1.25,
        PRICE_TABLE_AS_OF,
    ),
    (
        BillingBackend::Anthropic,
        "claude-mythos-5-1",
        10.0,
        50.0,
        0.025,
        1.25,
        PRICE_TABLE_AS_OF,
    ),
    (
        BillingBackend::Anthropic,
        "claude-opus-5-5",
        4.0,
        20.0,
        0.05,
        1.25,
        PRICE_TABLE_AS_OF,
    ),
    (
        BillingBackend::Anthropic,
        "claude-sonnet-5-5",
        2.0,
        10.0,
        0.05,
        1.25,
        PRICE_TABLE_AS_OF,
    ),
];

/// The `[pricing]` table read out of the FULL `kata.toml` text. It declares
/// only `pricing`, so every other top-level table passes unread: the closed
/// parse of the whole file is `ConfigManager`'s, which already ran on these
/// exact bytes before [`load_overrides_from_snapshot`] reads them.
#[derive(Clone, Debug, Default, serde::Deserialize)]
struct PricingConfigFile {
    #[serde(default)]
    pricing: PricingConfig,
}

/// Live operator overrides, installed by [`load_overrides_from_snapshot`].
/// `None` until the first load — [`rate_row`] treats that identically
/// to an empty override set (built-in `PRICE_TABLE` only).
static PRICE_OVERRIDES: OnceLock<Mutex<Arc<Vec<PriceOverride>>>> = OnceLock::new();

/// Install pricing from the exact configuration snapshot already parsed and
/// validated by `ConfigManager`.
///
/// `expected_digest` must be the BLAKE3 digest captured from that same read.
/// Verifying it here makes accidental mixing of config snapshots fail closed.
/// There is no reload: an installed main treats pricing edits as
/// restart-required and never reopens a replaceable config path.
pub fn load_overrides_from_snapshot(
    text: &str,
    source_path: impl AsRef<Path>,
    expected_digest: &str,
) -> KataResult<usize> {
    let source_path = source_path.as_ref();
    let actual_digest = blake3::hash(text.as_bytes()).to_hex().to_string();
    if actual_digest != expected_digest {
        return Err(KataError::Config(format!(
            "pricing snapshot digest mismatch for {}: expected {expected_digest}, got {actual_digest}",
            source_path.display()
        )));
    }
    parse_and_store_overrides(text, source_path)
}

fn parse_and_store_overrides(text: &str, source_path: &Path) -> KataResult<usize> {
    let parsed: PricingConfigFile = toml::from_str(text).map_err(|e| {
        KataError::Config(format!(
            "failed to parse pricing config at {}: {e}",
            source_path.display()
        ))
    })?;
    parsed.pricing.validate()?;
    let count = parsed.pricing.models.len();
    store_overrides(parsed.pricing.models);
    Ok(count)
}

fn store_overrides(rows: Vec<PriceOverride>) {
    let cell = PRICE_OVERRIDES.get_or_init(|| Mutex::new(Arc::new(Vec::new())));
    let mut guard = cell.lock().expect("pricing overrides lock poisoned");
    *guard = Arc::new(rows);
}

fn current_overrides() -> Arc<Vec<PriceOverride>> {
    match PRICE_OVERRIDES.get() {
        Some(cell) => Arc::clone(&cell.lock().expect("pricing overrides lock poisoned")),
        None => Arc::new(Vec::new()),
    }
}

/// Where a resolved rate came from — the provenance an
/// [`EstimateBasis`] reports.
///
/// Kept distinct from the rates themselves because the two sources differ in
/// what an operator can DO about a wrong figure: a built-in row is dated and
/// kata's to fix, an override is the operator's own and undatable by kata.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RateOrigin {
    /// An operator `[[pricing.models]]` row from `kata.toml`.
    OperatorOverride,
    /// A built-in [`PRICE_TABLE`] row, dated by its own `as_of` column.
    BuiltInTable {
        /// The `YYYY-MM` the row's source was read.
        as_of: &'static str,
    },
}

impl RateOrigin {
    fn basis(self) -> EstimateBasis {
        match self {
            Self::OperatorOverride => EstimateBasis::OperatorOverride,
            Self::BuiltInTable { as_of } => EstimateBasis::PriceTable {
                rates_as_of: smol_str::SmolStr::new_static(as_of),
            },
        }
    }
}

/// Resolve `(input_rate, output_rate, cache_read_mult, cache_write_mult)` plus
/// its [`RateOrigin`] for `(backend, model)`, consulting live operator
/// overrides BEFORE the built-in [`PRICE_TABLE`]. Returns `None` when neither
/// has a row — callers fall back to the conservative unknown-model estimate.
fn rate_row_with_origin(
    backend: BillingBackend,
    model: &str,
) -> Option<((f64, f64, f64, f64), RateOrigin)> {
    let overrides = current_overrides();
    for row in overrides.iter() {
        if row.backend == backend && row.model == model {
            return Some((
                (
                    row.input_rate_per_mtok,
                    row.output_rate_per_mtok,
                    row.cache_read_multiplier,
                    row.cache_write_multiplier,
                ),
                RateOrigin::OperatorOverride,
            ));
        }
    }
    for &(bt, name, input_rate, output_rate, cache_read_mult, cache_write_mult, as_of) in
        PRICE_TABLE
    {
        if bt == backend && name == model {
            return Some((
                (input_rate, output_rate, cache_read_mult, cache_write_mult),
                RateOrigin::BuiltInTable { as_of },
            ));
        }
    }
    None
}

/// [`rate_row_with_origin`] without the provenance, for the savings calculation
/// (which reports no basis).
fn rate_row(backend: BillingBackend, model: &str) -> Option<(f64, f64, f64, f64)> {
    rate_row_with_origin(backend, model).map(|(rates, _)| rates)
}

/// Set of `(BillingBackend, model)` pairs already warned about.
///
/// `#[doc(hidden)] pub` so the `pricing::testing` re-export module
/// can expose it to integration tests in
/// `crates/worker/tests/pricing_tests.rs` — they inspect the set
/// directly rather than relying on log-capture, which is
/// order-sensitive when nextest runs test functions in a single
/// process. Not part of the public API; reach for it via
/// `kata_worker::pricing::testing::UNKNOWN_WARNED`.
#[doc(hidden)]
pub static UNKNOWN_WARNED: OnceLock<Mutex<HashSet<(BillingBackend, String)>>> = OnceLock::new();

/// Return the estimated USD cost for one agent call.
///
/// Resolves the rate through operator `[[pricing.models]]` overrides first,
/// then the built-in [`PRICE_TABLE`] (see [`rate_row`]).
///
/// # When neither has a row, the result is an UPPER BOUND
///
/// The call logs a one-time warning per unique `(backend, model)`,
/// increments `kata_pricing_unknown_model_fallback_total{backend}`, and
/// falls back to a CONSERVATIVE frontier-tier estimate — $15.00/MTok input,
/// $75.00/MTok output, and cache reads AND writes at the FULL input rate
/// (no cache multipliers are known for an unmodeled model). It is emphatically
/// NOT `$0`.
///
/// Callers and anything that renders this number must treat it accordingly:
/// for an unpriced model the reported cost is a deliberately high bound, so
/// `cost_bound` and budgets trip EARLY — by roughly an order of magnitude
/// against a cheap model. That is the intended safety posture (the
/// unknown-model floor: an unmodeled model is assumed expensive), but it means an operator who
/// reads the figure as a measurement will conclude kata is broken. The
/// warn-once text and `docs/architecture/0001-replacement-architecture.md` both say so; keep them
/// in step with the constants below.
///
/// # Cache-aware pricing
///
/// The cost is the sum of:
///
/// * `input × input_rate`          — regular input tokens
/// * `output × output_rate`        — output tokens
/// * `cache_read × input_rate × cache_read_multiplier`
/// * `cache_write × input_rate × cache_write_multiplier`
///
/// `input` arrives already excluding cache hits and cache creations, so the
/// four lines are disjoint.
///
/// # Unit
///
/// The returned value is in **USD** (not micro-USD). A caller converts it with
/// `× 1_000_000` into the micro-USD unit every metered cost uses.
#[must_use]
pub fn lookup_cost_usd(backend: BillingBackend, model: &str, usage: TokenUsage) -> f64 {
    estimate_usd_with_basis(backend, model, usage).0
}

/// Classify ONE agent call into the metering trichotomy.
///
/// This is the single classifier: every stage-completion cost kata reports
/// comes through here, so the three arms are exhaustive by construction rather
/// than by each backend adapter re-deriving the same convention (and one path
/// getting a fourth answer by omission).
///
/// The order of the arms is load-bearing:
///
/// 1. **The provider stated a charge** → [`MeteredCost::Authoritative`]. Nothing
///    kata computes can beat the bill.
/// 2. **A subscription call** → [`MeteredCost::Unavailable`] at any token count:
///    flat-rate spend has no per-token price.
/// 3. **A billable call reported no usage to price** →
///    [`MeteredCost::Unavailable`]. This is the zero-token case: a stage
///    whose usage report failed to parse must not degrade to
///    `TokenUsage::default()`, priced to `$0.00`, contributing a silent `0`
///    to every running total and every cost bound. If `0` and "unknown" were
///    the same value, a hard cost policy could not fail closed on the second.
/// 4. **Otherwise** → [`MeteredCost::Estimated`], carrying which rate produced
///    it and (for a built-in row) how stale that rate is.
///
/// A [`BillingBackend`] is billable by construction: a `shell` or
/// `workspace_effect` stage, whose model spend is exactly zero and known, has no
/// billing key and never reaches this classifier (its charge is
/// `StageUsage::unbilled`).
///
/// Arm 4's unknown-model sub-case keeps the conservative frontier
/// floor and its warn-once — deliberately, and it is NOT arm 3. A floor
/// estimate over-states spend, so a bound evaluated against it trips
/// at-or-before the true charge; downgrading it to `Unavailable` would halt
/// every run against an unpriced model under a hard policy, which is a recourse
/// nobody could invoke. The figure is LABELLED as the upper bound it is.
#[must_use]
pub fn meter_call(
    backend: BillingBackend,
    model: &str,
    usage: TokenUsage,
    provider: ProviderCost,
    credential: kata_types::metering::CredentialMode,
) -> MeteredCost {
    if let Some(micro_usd) = provider.reported_micro_usd() {
        return MeteredCost::Authoritative { micro_usd };
    }
    // THE CREDENTIAL-MODE RULE: a
    // subscription-billed call has no per-token price an estimate can
    // claim, whatever the token counts — `Unavailable` naming the backend
    // and model, never an `Estimated` a hard bound would enforce as if it
    // were a measured spend.
    if credential == kata_types::metering::CredentialMode::Subscription {
        metrics::counter!(
            "kata_pricing_unmetered_call_total",
            "backend" => backend.label(),
            "reason" => "subscription",
        )
        .increment(1);
        return MeteredCost::Unavailable {
            backend: smol_str::SmolStr::new_static(backend.label()),
            model: smol_str::SmolStr::new(model),
        };
    }
    if usage.is_zero() {
        warn_unmetered_once(backend, model);
        metrics::counter!(
            "kata_pricing_unmetered_call_total",
            "backend" => backend.label(),
        )
        .increment(1);
        return MeteredCost::Unavailable {
            backend: smol_str::SmolStr::new_static(backend.label()),
            model: smol_str::SmolStr::new(model),
        };
    }
    let (usd, basis) = estimate_usd_with_basis(backend, model, usage);
    // Positive-definite and far inside u64 for any real prompt cost.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let micro_usd = (usd * 1_000_000.0) as u64;
    MeteredCost::Estimated { micro_usd, basis }
}

/// The per-token estimate for one call, paired with the provenance of the rate
/// that produced it. [`lookup_cost_usd`] is this without the provenance;
/// [`meter_call`] is this wrapped in the quality trichotomy.
fn estimate_usd_with_basis(
    backend: BillingBackend,
    model: &str,
    usage: TokenUsage,
) -> (f64, EstimateBasis) {
    if let Some(((input_rate, output_rate, cache_read_mult, cache_write_mult), origin)) =
        rate_row_with_origin(backend, model)
    {
        if let RateOrigin::BuiltInTable { as_of } = origin {
            warn_stale_price_table_once(as_of);
        }
        #[allow(clippy::cast_precision_loss)]
        let input_cost = usage.input as f64 * input_rate / 1_000_000.0;
        #[allow(clippy::cast_precision_loss)]
        let output_cost = usage.output as f64 * output_rate / 1_000_000.0;
        #[allow(clippy::cast_precision_loss)]
        let cache_read_cost = usage.cache_read as f64 * input_rate * cache_read_mult / 1_000_000.0;
        #[allow(clippy::cast_precision_loss)]
        let cache_write_cost =
            usage.cache_write as f64 * input_rate * cache_write_mult / 1_000_000.0;
        return (
            input_cost + output_cost + cache_read_cost + cache_write_cost,
            origin.basis(),
        );
    }
    // Unknown-model safety floor: an unknown (backend, model) must NOT silently cost $0 —
    // that hides real spend from budgets/bounds and the cost metrics. Fall back
    // to a CONSERVATIVE (deliberately high, frontier-tier) rate so an unknown
    // model is assumed expensive: budgets/bounds then trip early rather than
    // letting an unpriced model run unbounded.
    //
    // The cost this returns is therefore an UPPER BOUND, not a measurement, and
    // every operator-facing statement about it has to say so. Two recourses
    // replace the estimate with a real rate, and BOTH must be named wherever
    // this is explained: an operator `[[pricing.models]]` override in
    // `kata.toml` (no rebuild) and a built-in `PRICE_TABLE` row (source
    // change). Naming only the source change hides the one an operator can
    // actually invoke.
    warn_unknown_once(backend, model);
    // Labeled by backend so the counter answers "WHICH agent is running
    // unpriced", not merely "something was". Without a label an operator
    // reading a dashboard cannot tell an upper-bound cost from a measured
    // one — the fallback is otherwise indistinguishable on every surface
    // (`cost_micro_usd` in the completed output and the evidence record both
    // carry a bare number). Cardinality is
    // bounded by the `BillingBackend` enum. `model` is deliberately NOT a label:
    // it is per-stage operator input and would be unbounded; the warn-once
    // log line carries it instead.
    metrics::counter!(
        "kata_pricing_unknown_model_fallback_total",
        "backend" => backend.label(),
    )
    .increment(1);
    #[allow(clippy::cast_precision_loss)]
    let input_cost = usage.input as f64 * UNKNOWN_MODEL_FALLBACK_INPUT_RATE_PER_MTOK / 1_000_000.0;
    #[allow(clippy::cast_precision_loss)]
    let output_cost =
        usage.output as f64 * UNKNOWN_MODEL_FALLBACK_OUTPUT_RATE_PER_MTOK / 1_000_000.0;
    // No cache multipliers are known for an unmodeled backend — conservatively
    // charge cache reads + writes at the full input rate.
    #[allow(clippy::cast_precision_loss)]
    let cache_cost = (usage.cache_read + usage.cache_write) as f64
        * UNKNOWN_MODEL_FALLBACK_INPUT_RATE_PER_MTOK
        / 1_000_000.0;
    (
        input_cost + output_cost + cache_cost,
        EstimateBasis::UnknownModelFloor {
            model: smol_str::SmolStr::new(model),
        },
    )
}

/// Conservative per-million-token fallback rates for an unmodeled
/// `(backend, model)` (the unknown-model safety floor). Set at a frontier/Opus tier so an
/// unknown model is assumed EXPENSIVE — budgets and per-loop bounds trip early
/// rather than under-counting an unpriced model to $0.
const UNKNOWN_MODEL_FALLBACK_INPUT_RATE_PER_MTOK: f64 = 15.0;
const UNKNOWN_MODEL_FALLBACK_OUTPUT_RATE_PER_MTOK: f64 = 75.0;

/// Return the estimated USD savings from cache reads for one agent
/// call:
///
/// `cache_read × input_rate × (1 − cache_read_multiplier) / 1_000_000`
///
/// = "what you would have paid if these tokens were full input"
///   minus "what you actually paid for them as cache reads."
///
/// Cache writes are an upfront cost, not a savings — they're excluded
/// here so the counter stays positive-monotonic.
///
/// # Unknown `(backend, model)` returns `0.0`, and does not warn
///
/// A savings figure cannot be derived without a rate, so an unpriced model
/// yields `0.0` here even when `usage.cache_read` is large. This function
/// does NOT fire its own warn-once, and the reason is a call-ordering
/// property, not a structural guarantee: kata's ONLY production call site
/// (`crates/worker/src/agent_turn.rs`, in `cache_savings_micro_usd`) runs right
/// after `meter_agent_turn` meters the SAME `(backend, model)` through
/// [`meter_call`], whose estimate fires the warn-once for an unpriced model. A
/// direct caller that invokes this function ALONE — this is `pub` API —
/// observes `0.0` with no warning at all. If a second production call site
/// is ever added, it must either be preceded by the cost lookup or grow its
/// own signal; do not treat the silence here as self-justifying.
///
/// Unit is USD (not micro-USD); caller does the `× 1_000_000` conversion.
#[must_use]
pub fn cache_read_savings_usd(backend: BillingBackend, model: &str, usage: TokenUsage) -> f64 {
    if let Some((input_rate, _output_rate, cache_read_mult, _cache_write_mult)) =
        rate_row(backend, model)
    {
        #[allow(clippy::cast_precision_loss)]
        let savings = usage.cache_read as f64 * input_rate * (1.0 - cache_read_mult) / 1_000_000.0;
        return savings.max(0.0);
    }
    0.0
}

/// Set of `(BillingBackend, model)` pairs already warned about as UNMETERABLE —
/// the [`MeteredCost::Unavailable`] arm's warn-once ledger.
///
/// Separate from [`UNKNOWN_WARNED`] because the two say opposite things and
/// must not debounce each other: `UNKNOWN_WARNED` reports "priced at a
/// deliberately high floor", this one reports "not priced at all". A single
/// shared set would let whichever fired first silence the other for the life of
/// the process.
#[doc(hidden)]
pub static UNMETERED_WARNED: OnceLock<Mutex<HashSet<(BillingBackend, String)>>> = OnceLock::new();

/// The row dates the stale-price-table warning has fired for this process.
static STALE_TABLE_WARNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();

fn warn_unknown_once(backend: BillingBackend, model: &str) {
    let set = UNKNOWN_WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let key = (backend, model.to_string());
    let mut guard = set.lock().expect("pricing warn-once lock poisoned");
    if guard.insert(key) {
        tracing::warn!(
            backend = backend.label(),
            %model,
            fallback_input_rate_per_mtok = UNKNOWN_MODEL_FALLBACK_INPUT_RATE_PER_MTOK,
            fallback_output_rate_per_mtok = UNKNOWN_MODEL_FALLBACK_OUTPUT_RATE_PER_MTOK,
            "pricing: unpriced (backend, model) — NOT metered at 0. This model is \
             charged at the conservative frontier floor ($15.00/MTok input, \
             $75.00/MTok output, cache reads AND writes at the full input rate), \
             so every reported cost for it is an UPPER BOUND, not a measurement, \
             and `cost_bound` / budgets will trip EARLY — possibly by an order of \
             magnitude. To meter it for real, either add an operator override to \
             kata.toml (`[[pricing.models]]` with backend/model/\
             input_rate_per_mtok/output_rate_per_mtok — no restart-free reload, \
             pricing is restart-required) or add a `pricing::PRICE_TABLE` row."
        );
    }
}

/// Warn once per `(backend, model)` that a call could not be metered
/// AT ALL.
///
/// Distinct in wording from [`warn_unknown_once`] on purpose: that one says
/// "priced high"; this one says "not priced", and conflating the two is exactly
/// the ambiguity the metering trichotomy exists to remove. The log line is a
/// SECOND carrier for a fact that also reaches the `ExecutionRecord` — a log
/// line alone is never enough.
fn warn_unmetered_once(backend: BillingBackend, model: &str) {
    let set = UNMETERED_WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let key = (backend, model.to_string());
    let mut guard = set
        .lock()
        .expect("pricing unmetered warn-once lock poisoned");
    if guard.insert(key) {
        tracing::warn!(
            backend = backend.label(),
            %model,
            "pricing: UNMETERABLE call — the provider reported neither a charge nor any \
             token usage, so kata cannot say what this cost. It contributes NOTHING to \
             the run's cost (it is NOT $0), the running total is a LOWER BOUND, and a \
             HARD cost policy (`cost_bound` / `cost_budget(\"halt\", ..)`) on this run \
             HALTS rather than continue against a ceiling it cannot measure. A \
             `[[pricing.models]]` row cannot price a call that reported no usage. \
             Recourse: use a backend that reports token usage."
        );
    }
}

/// Warn once per process when the built-in [`PRICE_TABLE`] is older
/// than [`PRICE_TABLE_STALE_AFTER_MONTHS`].
///
/// The date also travels on every estimate as
/// [`EstimateBasis::PriceTable::rates_as_of`], which is the durable half; this
/// is the half that reaches an operator who never looks at a record.
fn warn_stale_price_table_once(as_of: &'static str) {
    let age = months_since(as_of, chrono::Utc::now());
    if age < PRICE_TABLE_STALE_AFTER_MONTHS {
        return;
    }
    let warned = STALE_TABLE_WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    if !warned
        .lock()
        .expect("pricing stale warn-once lock poisoned")
        .insert(as_of)
    {
        return;
    }
    tracing::warn!(
        price_table_as_of = as_of,
        age_months = age,
        stale_after_months = PRICE_TABLE_STALE_AFTER_MONTHS,
        "pricing: the built-in PRICE_TABLE list prices are {age} months old. Every \
         estimate derived from it reports `rates_as_of` so the staleness is visible on \
         the ExecutionRecord, but a cost bound evaluated against stale rates trips early \
         or late. Recourse: `[[pricing.models]]` overrides in kata.toml (no rebuild), or \
         refresh `pricing::PRICE_TABLE` and bump the rows' date."
    );
}

/// Test-only re-exports of items that are not part of the public
/// `pricing` API but are needed by integration tests in
/// `crates/worker/tests/pricing_tests.rs`. Hidden from rustdoc.
#[doc(hidden)]
pub mod testing {
    pub use super::{UNKNOWN_WARNED, UNMETERED_WARNED};
}

#[cfg(test)]
mod as_of_tests {
    use super::{
        PRICE_TABLE_AS_OF, PRICE_TABLE_STALE_AFTER_MONTHS, parse_year_month, price_table_age_months,
    };
    use chrono::TimeZone;

    fn at(year: i32, month: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(year, month, 1, 0, 0, 0)
            .single()
            .expect("valid date")
    }

    /// Fixed dates, never the wall clock: a staleness test that reads
    /// `Utc::now()` passes or fails by the calendar, which measures the day the
    /// gate ran rather than the code.
    #[test]
    fn age_is_whole_months_from_the_table_date() {
        assert_eq!(parse_year_month(PRICE_TABLE_AS_OF), Some((2026, 11)));
        assert_eq!(price_table_age_months(at(2026, 11)), 0);
        assert_eq!(price_table_age_months(at(2027, 2)), 3);
        assert_eq!(price_table_age_months(at(2027, 11)), 12);
    }

    /// A clock that precedes the table must read 0, not underflow. The table
    /// date is operator-visible input via the source, and a negative age would
    /// wrap to ~4 billion months and fire the stale warning permanently.
    #[test]
    fn a_clock_before_the_table_reads_zero_not_underflow() {
        assert_eq!(price_table_age_months(at(2025, 1)), 0);
        assert_eq!(price_table_age_months(at(2026, 10)), 0);
    }

    /// The staleness threshold is CROSSABLE and the boundary is exact.
    ///
    /// Two separate claims, and the first is the one that matters. A threshold
    /// no realistic elapsed time can reach — say 1200 months — would make the
    /// whole staleness mechanism dormant while reading as shipped, which is
    /// defect class (c): a verification satisfiable by observing nothing. So the
    /// constant is bounded here, with the reason, rather than merely chosen.
    #[test]
    fn the_stale_threshold_is_crossable_and_the_boundary_is_exact() {
        assert!(
            (1..=12).contains(&PRICE_TABLE_STALE_AFTER_MONTHS),
            "a price table must be able to go stale within a year of a release, or the \
             warning is a mechanism nothing can trigger; got {PRICE_TABLE_STALE_AFTER_MONTHS}"
        );

        // Exact boundary, at dates derived from the shipped constants rather
        // than hardcoded — `>=` fires AT the threshold, not one month later.
        let (year, month) = parse_year_month(PRICE_TABLE_AS_OF).expect("the shipped date parses");
        let months_after = |n: u32| {
            let total = month - 1 + n;
            at(
                year + i32::try_from(total / 12).expect("year fits"),
                total % 12 + 1,
            )
        };
        assert!(
            price_table_age_months(months_after(PRICE_TABLE_STALE_AFTER_MONTHS - 1))
                < PRICE_TABLE_STALE_AFTER_MONTHS,
            "one month before the threshold must NOT be stale"
        );
        assert!(
            price_table_age_months(months_after(PRICE_TABLE_STALE_AFTER_MONTHS))
                >= PRICE_TABLE_STALE_AFTER_MONTHS,
            "exactly at the threshold must be stale"
        );
    }

    /// A malformed constant degrades to age 0 (never stale) rather than
    /// panicking inside a metering call on the executor's hot path.
    #[test]
    fn a_malformed_table_date_does_not_panic() {
        assert_eq!(parse_year_month("not-a-date"), None);
        assert_eq!(parse_year_month("2026"), None);
        assert_eq!(parse_year_month("2026-04"), Some((2026, 4)));
    }
}
