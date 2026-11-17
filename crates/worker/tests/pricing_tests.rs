//! Extracted from `crates/worker/src/pricing.rs` inline `#[cfg(test)] mod tests`.
//!
//! Convention: pure integration test that imports through
//! `kata_worker::pricing` (public) plus the `testing` re-export for
//! the `UNKNOWN_WARNED` warn-once OnceLock that needs direct
//! inspection.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use smol_str::SmolStr;

use kata_core::ConfigManager;
use kata_types::agent::BillingBackend;
use kata_types::cache::TokenUsage;
use kata_types::config::{
    ApiAuthConfig, ApiConfig, KataConfig, NodeConfig, RuntimeConfig, WorkerPoolConfig,
    WorkerTransportConfig,
};

use kata_types::metering::{EstimateBasis, MeteredCost, MeteringQuality, ProviderCost};

use kata_worker::pricing::testing::UNKNOWN_WARNED;
use kata_worker::pricing::{
    PRICE_TABLE_AS_OF, cache_read_savings_usd, load_overrides_from_snapshot, lookup_cost_usd,
    meter_call,
};

/// Install `text` as the pricing snapshot, through the one install door, under
/// its own digest.
fn install_pricing(text: &str) -> kata_types::error::KataResult<usize> {
    load_overrides_from_snapshot(
        text,
        "kata.toml",
        blake3::hash(text.as_bytes()).to_hex().as_str(),
    )
}

fn config_with_pricing(model: &str, input_rate: f64) -> String {
    let config = KataConfig {
        node: NodeConfig {
            // Only the `oci` profile loads — the pricing snapshot lives behind
            // `ConfigManager::load`, so the fixture must carry the shipped `oci`
            // profile (`validate` does not require `[node] environment`; boot does).
            environment: None,
            output_bytes_ceiling: kata_types::execution_contract::NODE_OUTPUT_BYTES_CEILING,
            work_delta_bytes_ceiling: kata_types::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
            work_delta_entries_ceiling:
                kata_types::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
            capsule_memory_bytes_ceiling: None,
            capsule_process_count_ceiling: None,
            id: "pricing-test".into(),
            data_dir: "/tmp/kata-pricing-test".into(),
            work_tree_max_bytes: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES,
            work_tree_max_entries: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES,
            egress_allow: Vec::new(),
        },
        runtime: RuntimeConfig::default(),
        workers: WorkerPoolConfig {
            transports: vec![WorkerTransportConfig::SupervisedNode {}],
            dispatch_deadline_ms: 5_000,
            assignment_start_deadline_ms: 900_000,
            heartbeat_interval_ms: 2_500,
            heartbeat_grace_ms: 10_000,
            max_workers: 1,
        },
        api: ApiConfig {
            bind: "127.0.0.1:8400".into(),
            auth: ApiAuthConfig::Disabled {},
        },
        agents: BTreeMap::new(),
        vcs: kata_types::config::VcsConfig::default(),
        telemetry: kata_types::config::TelemetryConfig::default(),
        containment: kata_types::config::ContainmentConfig::default(),
        git_view: kata_types::config::GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    };
    // The row is appended as an operator writes it, not serialized from
    // `PriceOverride` — the type the loader under test parses it with — so the
    // serialized (empty) `[pricing]` table is dropped first.
    let mut document = toml::Value::try_from(&config).unwrap();
    document
        .as_table_mut()
        .expect("a KataConfig serializes to a TOML table")
        .remove("pricing");
    let mut text = toml::to_string_pretty(&document).unwrap();
    write!(
        text,
        r#"
[[pricing.models]]
backend = "anthropic"
model = "{model}"
input_rate_per_mtok = {input_rate:?}
output_rate_per_mtok = 0.0
cache_read_multiplier = 0.0
cache_write_multiplier = 1.0
"#
    )
    .expect("write pricing fixture");
    text
}

#[test]
fn unknown_model_falls_back_to_nonzero_conservative_cost() {
    // Unknown-model safety floor: an unknown model must NOT silently cost $0 (which hides
    // spend from budgets/bounds). It falls back to a conservative frontier-tier
    // estimate ($15/Mtok in, $75/Mtok out) so an unpriced model is assumed
    // expensive and budgets trip early.
    let usage = TokenUsage {
        input: 1_000,
        output: 500,
        ..TokenUsage::default()
    };
    let cost = lookup_cost_usd(
        BillingBackend::Anthropic,
        "anthropic-nonexistent-model-xyz",
        usage,
    );
    // 1_000 input @ $15/Mtok + 500 output @ $75/Mtok.
    let expected = 1_000.0 * 15.0 / 1_000_000.0 + 500.0 * 75.0 / 1_000_000.0;
    assert!(
        cost > 0.0 && (cost - expected).abs() < 1e-9,
        "unknown model must use the conservative fallback (~{expected}), got {cost}"
    );
}

/// The unpriced-model fallback must be OBSERVABLE, and observable per
/// backend. `lookup_cost_usd` returning a conservative upper bound is only
/// half the contract: if nothing on an operator surface says the number is an
/// upper bound, an operator reads a bounded estimate as a measurement. A bare
/// (unlabeled) counter could say THAT a fallback happened but not WHICH backend
/// was running unpriced.
///
/// Counterfactual: drop the `"backend" => backend.label()` label from the
/// `metrics::counter!` in `lookup_cost_usd` and the snapshot key carries no
/// `backend` label — fails. Delete the counter entirely and the filter yields
/// an empty vec — also fails.
#[test]
fn unknown_model_fallback_counter_is_labeled_by_backend() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let usage = TokenUsage {
        input: 1_000,
        output: 500,
        ..TokenUsage::default()
    };

    metrics::with_local_recorder(&recorder, || {
        let _ = lookup_cost_usd(
            BillingBackend::Anthropic,
            "counter-label-sentinel-anthropic",
            usage,
        );
    });

    let mut seen: Vec<(String, u64)> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _unit, _desc, value)| {
            let k = key.key();
            if k.name() != "kata_pricing_unknown_model_fallback_total" {
                return None;
            }
            let backend = k
                .labels()
                .find(|l| l.key() == "backend")
                .map(|l| l.value().to_string())?;
            match value {
                DebugValue::Counter(n) => Some((backend, n)),
                _ => None,
            }
        })
        .collect();
    seen.sort();

    assert_eq!(
        seen,
        vec![("anthropic".to_string(), 1)],
        "the fallback counter must carry a per-backend label so an operator \
         can see WHICH backend is metering an upper bound"
    );
}

/// `claude-haiku-5-5` has NO `PRICE_TABLE` row (deliberately — it is priced
/// by each request's prompt length, which a turn's summed usage cannot say,
/// and a fabricated rate is worse than an honest upper bound). Pin what that
/// actually costs so the number in the operator warning is the number the code
/// produces: the floor charges a cached read at the FULL floor input rate.
///
/// Counterfactual: add an `(Anthropic, "claude-haiku-5-5", …)` row to
/// `PRICE_TABLE` and this fails — which is the point. If someone invents a
/// rate for this model, that has to be a deliberate act, not a silent one.
#[test]
fn an_unpriced_model_upper_bound_is_the_frontier_floor_not_a_measurement() {
    let usage = TokenUsage {
        input: 12_507,
        cache_read: 4_736,
        output: 25,
        cache_write: 0,
    };
    let cost = lookup_cost_usd(BillingBackend::Anthropic, "claude-haiku-5-5", usage);
    // Floor: $15/MTok input, $75/MTok output, cache read+write at the FULL
    // input rate (no cache multipliers are known for an unmodeled model).
    let expected = (12_507.0 * 15.0 + 25.0 * 75.0 + 4_736.0 * 15.0) / 1_000_000.0;
    assert!(
        (cost - expected).abs() < 1e-9,
        "an unpriced model must meter at the conservative floor \
         (~${expected:.4} for one trivial prompt), got ${cost:.4}"
    );
    // Guard the headline: this is ~26 cents for "say OK". That number is an
    // UPPER BOUND, and the warn-once must say so — an operator who reads it
    // as a measurement concludes kata is broken.
    assert!(
        cost > 0.25 && cost < 0.27,
        "sanity: the trivial-prompt upper bound should land near $0.26, got ${cost:.4}"
    );
}

#[test]
fn unknown_tuple_deduplicated_in_warn_set() {
    let usage = TokenUsage {
        input: 1,
        output: 1,
        ..TokenUsage::default()
    };
    // A model string unique to this test, with NO `PRICE_TABLE` row, so it is
    // genuinely unknown and exercises the conservative-fallback + warn-once
    // path without other test functions polluting this check.
    let model = "dedup-sentinel-model-b1fu4d";
    // Return values intentionally unused — we're testing the side-effect
    // of inserting into the warn-once set, not the return value.
    let _ = lookup_cost_usd(BillingBackend::Anthropic, model, usage);
    let _ = lookup_cost_usd(BillingBackend::Anthropic, model, usage);

    let set = UNKNOWN_WARNED
        .get()
        .expect("OnceLock must be initialized after any lookup_cost_usd call");
    let guard = set.lock().expect("lock");
    let key = (BillingBackend::Anthropic, model.to_string());
    // Count occurrences of our sentinel key. A HashSet stores each element
    // at most once, so this is 0 (never inserted) or 1 (inserted exactly
    // once). Two back-to-back unknown lookups with the same key must
    // produce exactly 1, confirming the warn-once dedup fired correctly.
    let count = guard.iter().filter(|k| *k == &key).count();
    assert_eq!(
        count, 1,
        "warn-once dedup failed: expected exactly 1 entry for \
         (Anthropic, {model:?}) after two identical unknown lookups, \
         found {count}"
    );
}

// ----- cache-aware pricing tests --------------------------------------------

/// An operator row under `model` carrying cache multipliers no built-in row
/// does (0.10× read, 1.25× write).
fn install_cache_multiplier_row(model: &str) {
    install_pricing(&format!(
        "[[pricing.models]]\nbackend = \"anthropic\"\nmodel = \"{model}\"\n\
         input_rate_per_mtok = 3.00\noutput_rate_per_mtok = 15.00\n\
         cache_read_multiplier = 0.10\ncache_write_multiplier = 1.25\n"
    ))
    .expect("load the cache-multiplier row");
}

#[test]
fn a_row_charges_both_cache_multipliers() {
    // input $3.00/M, output $15.00/M, cache_read 0.10×, cache_write 1.25×.
    // With 1M input + 0M output + 1M cache_read + 1M cache_write the cost is:
    //   $3.00 + $0 + (1M × $3.00 × 0.10 / 1M) + (1M × $3.00 × 1.25 / 1M)
    //   = $3.00 + $0.30 + $3.75 = $7.05
    const MODEL: &str = "cache-multiplier-sentinel";
    install_cache_multiplier_row(MODEL);
    let usage = TokenUsage {
        input: 1_000_000,
        output: 0,
        cache_read: 1_000_000,
        cache_write: 1_000_000,
    };
    let cost = lookup_cost_usd(BillingBackend::Anthropic, MODEL, usage);
    let expected = 7.05_f64;
    assert!(
        (cost - expected).abs() < 1e-9,
        "expected {expected:.6}, got {cost:.6}"
    );
}

#[test]
fn disjoint_token_counts_are_not_double_charged() {
    // The four token lines are disjoint: `input` already EXCLUDES cache hits
    // and cache creations. So input=100, cache_read=1000, cache_write=200 at
    // an input rate of $3/M costs
    //   100 × $3/M + 1000 × $0.30/M + 200 × $3.75/M
    //   = $0.0003 + $0.0003 + $0.00075 = $0.00135
    const MODEL: &str = "disjoint-counts-sentinel";
    install_cache_multiplier_row(MODEL);
    let usage = TokenUsage {
        input: 100,
        output: 0,
        cache_read: 1_000,
        cache_write: 200,
    };
    let cost = lookup_cost_usd(BillingBackend::Anthropic, MODEL, usage);
    let expected = (100.0 * 3.0 + 1000.0 * 0.30 + 200.0 * 3.75) / 1_000_000.0;
    assert!(
        (cost - expected).abs() < 1e-12,
        "disjoint counts must sum without double-charging: \
         expected {expected:.12}, got {cost:.12}"
    );
}

#[test]
fn cache_read_savings_formula() {
    // claude-sonnet-5-5 input rate $2.00/M, cache_read multiplier 0.05×.
    // Savings on 1M cache_read: 1M × $2.00 × (1 − 0.05) / 1M = $1.90.
    let usage = TokenUsage {
        input: 0,
        output: 0,
        cache_read: 1_000_000,
        cache_write: 0,
    };
    let savings = cache_read_savings_usd(BillingBackend::Anthropic, "claude-sonnet-5-5", usage);
    let expected = 1.90_f64;
    assert!(
        (savings - expected).abs() < 1e-9,
        "expected savings {expected:.6}, got {savings:.6}"
    );
}

#[test]
fn cache_read_savings_zero_on_unknown_model() {
    let usage = TokenUsage {
        input: 0,
        output: 0,
        cache_read: 1_000_000,
        cache_write: 0,
    };
    let savings = cache_read_savings_usd(BillingBackend::Anthropic, "no-such-model", usage);
    #[allow(clippy::float_cmp)]
    let exact_zero = savings == 0.0;
    assert!(
        exact_zero,
        "unknown model must yield 0.0 savings, got {savings}"
    );
}

// ----- runtime-reloadable pricing (kata.toml [pricing] overrides) ----------

#[test]
fn absent_config_falls_back_to_builtin_table() {
    // No `load_overrides_from_snapshot` call for this sentinel model in this
    // (fresh, nextest-per-test) process — must resolve via the built-in
    // PRICE_TABLE row, unaffected by pricing overrides never being loaded.
    let usage = TokenUsage {
        input: 1_000_000,
        output: 500_000,
        ..TokenUsage::default()
    };
    // claude-sonnet-5-5: 1M input @ $2/M + 0.5M output @ $10/M = $7.00.
    let cost = lookup_cost_usd(BillingBackend::Anthropic, "claude-sonnet-5-5", usage);
    assert!(
        (cost - 7.00_f64).abs() < 1e-9,
        "expected built-in $7.00 rate with no config loaded, got {cost}"
    );
}

#[test]
fn config_supplied_price_overrides_builtin_table() {
    let usage = TokenUsage {
        input: 1_000_000,
        output: 500_000,
        ..TokenUsage::default()
    };

    // Built-in rate for claude-sonnet-5-5 is $2.00/$10.00 per Mtok -> $7.00.
    let builtin_cost = lookup_cost_usd(BillingBackend::Anthropic, "claude-sonnet-5-5", usage);
    assert!((builtin_cost - 7.00_f64).abs() < 1e-9);

    let n = install_pricing(
        r#"
[[pricing.models]]
backend = "anthropic"
model = "claude-sonnet-5-5"
input_rate_per_mtok = 1.00
output_rate_per_mtok = 2.00
cache_read_multiplier = 0.0
cache_write_multiplier = 1.0
"#,
    )
    .expect("load overrides");
    assert_eq!(n, 1, "expected exactly one override row loaded");

    let overridden_cost = lookup_cost_usd(BillingBackend::Anthropic, "claude-sonnet-5-5", usage);
    // 1M input @ $1/M + 0.5M output @ $2/M = $1.00 + $1.00 = $2.00
    let expected = 2.00_f64;
    assert!(
        (overridden_cost - expected).abs() < 1e-9,
        "expected overridden cost {expected}, got {overridden_cost}"
    );
    assert!(
        (overridden_cost - builtin_cost).abs() > 1e-9,
        "override must actually change the cost, not coincide with the built-in rate"
    );
}

#[test]
fn validated_snapshot_pricing_ignores_post_validation_path_replacement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kata.toml");
    let model = "snapshot-toctou-sentinel";
    let accepted = config_with_pricing(model, 4.0);
    std::fs::write(&path, &accepted).unwrap();
    let manager = ConfigManager::load(&path).expect("validate initial config snapshot");
    let accepted_digest = manager
        .initial_content_digest()
        .expect("loaded snapshot digest")
        .to_string();

    // Replace the path after validation with a different, individually valid
    // price. Installed startup must consume ConfigManager's retained snapshot.
    std::fs::write(&path, config_with_pricing(model, 99.0)).unwrap();
    load_overrides_from_snapshot(
        manager.initial_content().expect("retained config content"),
        manager.path(),
        &accepted_digest,
    )
    .expect("load pricing from accepted snapshot");

    let usage = TokenUsage {
        input: 1_000_000,
        ..TokenUsage::default()
    };
    let cost = lookup_cost_usd(BillingBackend::Anthropic, model, usage);
    assert!((cost - 4.0).abs() < 1e-9, "replacement path won: {cost}");
    assert_ne!(
        blake3::hash(std::fs::read_to_string(&path).unwrap().as_bytes())
            .to_hex()
            .as_str(),
        accepted_digest,
        "adversarial replacement must actually differ from accepted identity"
    );
}

#[test]
fn pricing_snapshot_rejects_mixed_digest_identity() {
    let text = config_with_pricing("snapshot-digest-mismatch", 3.0);
    let error = load_overrides_from_snapshot(&text, "kata.toml", "not-the-snapshot-digest")
        .expect_err("mixed snapshot identity must fail closed")
        .to_string();
    assert!(
        error.contains("pricing snapshot digest mismatch"),
        "{error}"
    );
}

// ── The metering trichotomy, at the single classifier ──────────────────────
//
// Every test below asserts on `meter_call`, which is the ONE place
// authoritative / estimated / unavailable is decided. Asserting here rather
// than on each backend adapter is deliberate: a per-adapter convention is
// exactly what lets one path acquire a fourth answer by omission.

/// THE ZERO-TOKEN PROOF.
///
/// A billable backend that reports neither a charge nor any token usage is
/// UNMETERABLE. Priced, the same input would produce `$0.00`, which every
/// downstream consumer reads as *free*: a cost of exactly `0` that means
/// "unknown" is the ambiguous-value defect, and a backend that degrades a
/// missing or garbled usage event to `TokenUsage::default()` (so an accounting
/// gap never fails a stage) produces exactly that input.
///
/// COUNTERFACTUAL: delete the `if usage.is_zero()` arm from
/// `pricing::meter_call` and this fails — `meter_call` returns
/// `Estimated { micro_usd: 0, .. }`, `chargeable_micro_usd()` becomes `Some(0)`,
/// and the run reports a free stage.
#[test]
fn a_billable_call_with_no_usage_is_unavailable_not_zero() {
    let cost = meter_call(
        BillingBackend::Anthropic,
        "claude-sonnet-5-5",
        TokenUsage::default(),
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::ApiKey,
    );
    assert_eq!(
        cost,
        MeteredCost::Unavailable {
            backend: SmolStr::new("anthropic"),
            model: SmolStr::new("claude-sonnet-5-5"),
        },
        "a billable call with no usage must report UNMETERABLE, not $0"
    );
    assert_eq!(
        cost.chargeable_micro_usd(),
        None,
        "and it must present no number at all — `Some(0)` is the defect"
    );
    assert_eq!(cost.quality(), MeteringQuality::Unavailable);
}

/// An unpriced model's floor figure, LABELLED.
///
/// The same ~$0.26 figure `an_unpriced_model_upper_bound_is_the_frontier_floor_not_a_measurement`
/// pins, but this asserts the fact that figure was missing: that it is an
/// ESTIMATE from the unknown-model floor, and that the basis names the exact
/// model string an operator puts in a `[[pricing.models]]` row. A count or a
/// log line an operator cannot act on is a report, not a recourse.
///
/// COUNTERFACTUAL: return `EstimateBasis::PriceTable { .. }` from the floor arm
/// of `pricing::estimate_usd_with_basis` and this fails — the record would claim
/// a shipped rate produced a number no shipped rate produced.
#[test]
fn an_unpriced_model_is_estimated_at_the_floor_and_names_the_missing_row() {
    let usage = TokenUsage {
        input: 12_505,
        cache_read: 4_736,
        output: 35,
        cache_write: 0,
    };
    let cost = meter_call(
        BillingBackend::Anthropic,
        "claude-haiku-5-5",
        usage,
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::ApiKey,
    );
    let MeteredCost::Estimated { micro_usd, basis } = &cost else {
        panic!("an unpriced model with REAL tokens is estimable, got {cost:?}");
    };
    assert_eq!(
        basis,
        &EstimateBasis::UnknownModelFloor {
            model: SmolStr::new("claude-haiku-5-5"),
        },
        "the basis must name the model with no rate — that string IS the recourse"
    );
    // ~$0.26 for one trivial prompt.
    assert!(
        (250_000..270_000).contains(micro_usd),
        "the trivial-prompt upper bound should land near $0.26, got {micro_usd} micro-USD"
    );
    // An estimate stays Estimated — it over-states, so a bound trips
    // at-or-before the true charge. Downgrading it to Unavailable would halt
    // every unpriced model under a cost bound.
    assert_eq!(cost.quality(), MeteringQuality::Estimated);
}

/// A priced model reports the SHIPPED table's date, so an operator reading a
/// record can tell how stale the arithmetic behind a cost is.
///
/// COUNTERFACTUAL: fill `rates_as_of` from anything other than
/// `PRICE_TABLE_AS_OF` and this fails. `2026-11` prices evaluated in `2027-03`
/// trip a bound early or late and nothing else on any surface says which.
#[test]
fn a_priced_model_reports_the_table_date_it_was_priced_from() {
    let usage = TokenUsage {
        input: 1_000_000,
        ..TokenUsage::default()
    };
    let cost = meter_call(
        BillingBackend::Anthropic,
        "claude-sonnet-5-5",
        usage,
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::ApiKey,
    );
    assert_eq!(
        cost,
        MeteredCost::Estimated {
            // claude-sonnet-5-5's input rate is $2.00/MTok.
            micro_usd: 2_000_000,
            basis: EstimateBasis::PriceTable {
                rates_as_of: SmolStr::new(PRICE_TABLE_AS_OF),
            },
        },
    );
}

/// A provider-stated charge is AUTHORITATIVE and beats the table, including a
/// stated `$0`.
///
/// The stated-zero case is load-bearing and subtle: a turn whose vendor states no
/// charge surfaces `Unstated` (not `Reported { micro_usd: 0 }`), so the estimate
/// engages. But when a backend genuinely does state `$0`, kata does not overrule
/// a bill.
///
/// COUNTERFACTUAL: move the `provider.reported_micro_usd()` arm below the
/// `usage.is_zero()` arm in `meter_call` and the middle assertion fails — a
/// provider that billed $7 for an empty turn would read as unmeasurable.
#[test]
fn a_provider_stated_charge_is_authoritative_and_wins() {
    let usage = TokenUsage {
        input: 1_000_000,
        ..TokenUsage::default()
    };
    assert_eq!(
        meter_call(
            BillingBackend::Anthropic,
            "claude-sonnet-5-5",
            usage,
            ProviderCost::Reported { micro_usd: 55_400 },
            kata_types::metering::CredentialMode::ApiKey,
        ),
        MeteredCost::Authoritative { micro_usd: 55_400 },
        "the bill beats the table's $2.00 estimate for the same tokens"
    );
    assert_eq!(
        meter_call(
            BillingBackend::Anthropic,
            "claude-sonnet-5-5",
            TokenUsage::default(),
            ProviderCost::Reported { micro_usd: 7 },
            kata_types::metering::CredentialMode::ApiKey,
        ),
        MeteredCost::Authoritative { micro_usd: 7 },
        "a stated charge on a zero-usage turn is still a stated charge"
    );
    assert_eq!(
        meter_call(
            BillingBackend::Anthropic,
            "claude-sonnet-5-5",
            TokenUsage::default(),
            ProviderCost::Reported { micro_usd: 0 },
            kata_types::metering::CredentialMode::ApiKey,
        ),
        MeteredCost::Authoritative { micro_usd: 0 },
        "a provider that states $0 has made a claim; kata does not overrule a bill"
    );
}

/// An operator `[[pricing.models]]` row reports `OperatorOverride`, NOT a
/// `PriceTable` date kata cannot vouch for — and it RESCUES a model that would
/// otherwise hit the unknown-model floor, which is the recourse every
/// unpriced-model message names. A recourse nobody can invoke is defect class
/// (b), so it is asserted rather than merely documented.
///
/// COUNTERFACTUAL: return `RateOrigin::BuiltInTable.basis()` for an override in
/// `pricing::rate_row_with_origin` and this fails on the basis; delete the
/// override lookup entirely and it fails on the floor comparison.
#[test]
fn an_operator_override_reports_its_own_basis_and_rescues_an_unpriced_model() {
    const MODEL: &str = "override-only-model";
    let usage = TokenUsage {
        input: 1_000_000,
        ..TokenUsage::default()
    };

    // Before the override, this model has no row at all → the frontier floor.
    let floored = meter_call(
        BillingBackend::Anthropic,
        MODEL,
        usage,
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::ApiKey,
    );
    assert_eq!(
        floored,
        MeteredCost::Estimated {
            micro_usd: 15_000_000,
            basis: EstimateBasis::UnknownModelFloor {
                model: SmolStr::new(MODEL),
            },
        },
        "sanity: with no row this model must hit the $15/MTok floor"
    );

    install_pricing(&config_with_pricing(MODEL, 2.00)).expect("load overrides");

    let cost = meter_call(
        BillingBackend::Anthropic,
        MODEL,
        usage,
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::ApiKey,
    );
    assert_eq!(
        cost,
        MeteredCost::Estimated {
            micro_usd: 2_000_000,
            basis: EstimateBasis::OperatorOverride,
        },
        "an operator-supplied rate must report OperatorOverride — kata cannot date it — \
         and must replace the floor, which is the whole point of the recourse"
    );

    // Restore the built-in-only state: the override store is a process-wide
    // OnceLock, so leaving a row installed would leak into any test that runs
    // after this one in the same process.
    install_pricing("").expect("clear overrides");
}

/// THE CREDENTIAL-MODE RULE: a subscription-billed call has no per-token price
/// an estimate can claim — `meter_call` answers `Unavailable` naming the
/// backend and model, whatever the token counts, never an `Estimated` a hard
/// bound would enforce as if it were a measured spend.
#[test]
fn a_subscription_call_is_unavailable_at_any_token_count() {
    let usage = TokenUsage {
        input: 9_000,
        output: 900,
        cache_read: 0,
        cache_write: 0,
    };
    let cost = meter_call(
        BillingBackend::Anthropic,
        "vendor/small",
        usage,
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::Subscription,
    );
    assert_eq!(
        cost,
        MeteredCost::Unavailable {
            backend: smol_str::SmolStr::new("anthropic"),
            model: smol_str::SmolStr::new("vendor/small"),
        },
        "a subscription cannot be priced per-token — never an estimate: {cost:?}"
    );
    // And the same usage under `ApiKey` still prices — the mode is the whole
    // difference, so the contrast is asserted in the same cell.
    let priced = meter_call(
        BillingBackend::Anthropic,
        "vendor/small",
        usage,
        ProviderCost::Unstated,
        kata_types::metering::CredentialMode::ApiKey,
    );
    assert!(
        matches!(priced, MeteredCost::Estimated { .. }),
        "the identical call under ApiKey still estimates — the mode is what changed: {priced:?}"
    );
}

/// **THE PRICING INSTALL DOOR REFUSES A RATE THAT IS NOT A FINITE, NON-NEGATIVE
/// NUMBER**, re-running the check `KataConfig::validate` runs at config load: a NaN row
/// would price every call it matches at NaN. The refusal names the row and field.
///
/// **Watched red:** with the `validate` call absent from `parse_and_store_overrides`,
/// the NaN row loaded.
#[test]
fn a_nan_pricing_rate_is_refused_by_the_snapshot_loader() {
    let error = install_pricing(
        "[[pricing.models]]\nbackend = \"anthropic\"\nmodel = \"nan-rate-sentinel\"\n\
         input_rate_per_mtok = nan\noutput_rate_per_mtok = 0.0\ncache_read_multiplier = 0.0\n\
         cache_write_multiplier = 1.0\n",
    )
    .expect_err("a NaN rate must not install")
    .to_string();
    assert!(
        error.contains("pricing.models[0].input_rate_per_mtok"),
        "{error}"
    );
}

/// **Every built-in Anthropic row charges each token class at the page's own
/// price.** The figures below are written out from Anthropic's pricing table
/// (<https://platform.claude.com/docs/en/about-claude/pricing>, fetched
/// 2026-11-02; the Fable 5.2 and Mythos 5.2 rows 2026-11-16) as `$ / MTok` for base input, 5-minute cache writes, cache hits
/// and output — not derived from the table's multipliers — and one million
/// tokens of each class alone must cost exactly that, dated
/// `PRICE_TABLE_AS_OF`. `claude-haiku-5-5` (priced per request's prompt
/// length) and `claude-fable-5-5` (on neither Anthropic page) have no row and
/// are estimated at the floor.
///
/// **Would red if:** a row's rate or multiplier disagreed with the page (a
/// cache read at the standard 0.1x on Sonnet 5.5, a write at the 1-hour 2x),
/// or a row were dated other than by the table's date (red before the Fable 5.2
/// and Mythos 5.2 rows: both estimated at the unknown-model floor).
#[test]
fn the_anthropic_rows_charge_each_class_at_the_pages_price() {
    // (model, base input, 5m cache write, cache hit, output) — $ per MTok.
    for (model, input, write, read, output) in [
        ("claude-fable-5-2", 8.0, 10.0, 0.20, 40.0),
        ("claude-mythos-5-2", 8.0, 10.0, 0.20, 40.0),
        ("claude-fable-5-1", 10.0, 12.50, 0.25, 50.0),
        ("claude-mythos-5-1", 10.0, 12.50, 0.25, 50.0),
        ("claude-opus-5-5", 4.0, 5.0, 0.20, 20.0),
        ("claude-sonnet-5-5", 2.0, 2.50, 0.10, 10.0),
    ] {
        for (class, usage, dollars) in [
            (
                "input",
                TokenUsage {
                    input: 1_000_000,
                    ..TokenUsage::default()
                },
                input,
            ),
            (
                "cache write",
                TokenUsage {
                    cache_write: 1_000_000,
                    ..TokenUsage::default()
                },
                write,
            ),
            (
                "cache read",
                TokenUsage {
                    cache_read: 1_000_000,
                    ..TokenUsage::default()
                },
                read,
            ),
            (
                "output",
                TokenUsage {
                    output: 1_000_000,
                    ..TokenUsage::default()
                },
                output,
            ),
        ] {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let micro_usd = (dollars * 1_000_000.0_f64).round() as u64;
            assert_eq!(
                meter_call(
                    BillingBackend::Anthropic,
                    model,
                    usage,
                    ProviderCost::Unstated,
                    kata_types::metering::CredentialMode::ApiKey,
                ),
                MeteredCost::Estimated {
                    micro_usd,
                    basis: EstimateBasis::PriceTable {
                        rates_as_of: SmolStr::new(PRICE_TABLE_AS_OF),
                    },
                },
                "{model}: one million {class} tokens cost ${dollars}"
            );
        }
    }
    for model in ["claude-haiku-5-5", "claude-fable-5-5"] {
        assert!(
            matches!(
                meter_call(
                    BillingBackend::Anthropic,
                    model,
                    TokenUsage {
                        input: 1,
                        ..TokenUsage::default()
                    },
                    ProviderCost::Unstated,
                    kata_types::metering::CredentialMode::ApiKey,
                ),
                MeteredCost::Estimated {
                    basis: EstimateBasis::UnknownModelFloor { .. },
                    ..
                }
            ),
            "{model} has no row"
        );
    }
}
