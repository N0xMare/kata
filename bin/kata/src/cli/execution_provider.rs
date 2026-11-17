//! `kata execution-provider list | inspect | certify` — the operator's
//! window onto the containment trust model.
//!
//! # Two axes, deliberately kept apart
//!
//! Every subcommand reports both and never conflates them:
//!
//! * **What this BUILD ships** — `ExecBackend::provider_posture()` in
//!   `kata-types`. A compile-time constant of the binary; identical on every
//!   host.
//! * **What this HOST delivers** — `kata_worker::sandbox_posture::observe()`
//!   (reads, no container) and, for `certify`,
//!   `kata_worker::oci_runtime::certified_oci_route()` (the one certification
//!   the worker's capsule-route admission runs, functional probe included).
//!
//! A backend can ship a certified-containment runtime (build axis) on a host
//! that cannot deliver it (host axis). Reporting one as the other is how an
//! operator ends up believing a stage was contained.
//!
//! # `inspect` reports; `certify` also judges
//!
//! Both emit the same posture document. `certify` additionally carries the
//! certification's verdict and exits non-zero when it refuses, so a shell can
//! branch on it. Its evidence is the certification's own refusal token and
//! sentence, never a second wording.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use kata_types::sandbox::{ExecBackend, ExecProviderPosture};
use kata_worker::sandbox_posture::ContainmentPosture;
use serde::Serialize;

use super::output::OutputFormat;
use super::types::ExecutionProviderCmd;

/// The closed world of containment providers, in declaration order.
///
/// # This DERIVES the list
///
/// A hand-typed `&[ExecBackend]` is not exhaustively matched by anything: its
/// consumers are `.iter().find(..)` (below) and `.iter().map(row)`, and `row`
/// matches exhaustively on `ExecProviderPosture`, a different enum. A new
/// `ExecBackend` variant would compile cleanly and be ABSENT from the surface
/// whose entire purpose is making the containment trust model inspectable:
/// `list` would not name it, and `inspect`/`certify` would refuse its spelling
/// as *"unknown execution provider"* while the parser accepted it.
///
/// Derivation from [`strum::IntoEnumIterator`] leaves nothing to notice: an
/// added variant is in this list before anyone reads this comment. `EnumIter`
/// iterates in declaration order, so `list`'s order is the enum's.
fn all_backends() -> impl Iterator<Item = ExecBackend> {
    ExecBackend::all()
}

/// One row of `execution-provider list`: what the BUILD ships for a backend.
#[derive(Debug, Serialize)]
pub struct ProviderRow {
    /// The backend's stable spelling — the token the execution IR and the
    /// assignment frame carry, read from `ExecBackend::authored_spelling()` so a
    /// listing and the wire cannot name different tokens.
    ///
    /// NOT a thing an operator writes: no authoring surface spells a backend at
    /// all. A `sandbox_profile(..)` is always
    /// `oci` — its signature declares no `exec` keyword, so starlark refuses
    /// one as an extra named parameter — and `stage(sandbox = "host")` is the
    /// one opt-out.
    pub exec: &'static str,
    /// The build-axis posture, as its stable wire label.
    pub posture: &'static str,
    /// What that posture means, in one sentence.
    pub summary: &'static str,
    /// The refusal a DECODED PROGRAM naming this backend meets, when this build
    /// ships no runtime for it. Quoted from the ONE authority so this listing and
    /// the three enforcement points cannot drift.
    ///
    /// A backend cannot be declared, so the population that
    /// meets this refusal is durable bytes and in-process definitions, never a
    /// pack that loads today.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
}

/// `execution-provider list` / `inspect` payload.
#[derive(Debug, Serialize)]
pub struct ProviderReport {
    /// Discriminates the two shapes for a machine reader without a schema
    /// version — the same `summary_kind` convention `DoctorReport` uses.
    pub summary_kind: &'static str,
    /// Every backend this build knows, with its build-axis posture.
    pub providers: Vec<ProviderRow>,
    /// The measured HOST posture. Present on `inspect`/`certify`; absent on
    /// `list`, which asks only what the build ships.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_containment: Option<ContainmentPosture>,
    /// Which backend `inspect`/`certify` was asked about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inspected: Option<&'static str>,
    /// `certify`'s measurement of the rootless-OCI route — present only when
    /// the inspected backend's build posture is `certified_containment`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certification: Option<CertificationReport>,
    /// `certify`'s verdict. `None` for `list`/`inspect`, which report without
    /// judging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified: Option<bool>,
    /// Why [`Self::certified`] is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

fn row(backend: &ExecBackend) -> ProviderRow {
    let (posture, summary) = match backend.provider_posture() {
        ExecProviderPosture::CertifiedContainment => (
            "certified_containment",
            "a containment runtime is compiled into this build and confines the action",
        ),
        ExecProviderPosture::Unconfined => (
            "unconfined",
            "a runtime is compiled in and provides NO containment — the action runs with full \
             ambient host authority. An honest declarable posture, never a silent downgrade.",
        ),
        ExecProviderPosture::UnsupportedInThisBuild => (
            "unsupported_in_this_build",
            "no runtime for this backend is compiled into this build; declaring it is a \
             load-time refusal",
        ),
    };
    ProviderRow {
        exec: backend.authored_spelling(),
        posture,
        summary,
        unsupported_reason: backend.unsupported_in_this_build_reason(),
    }
}

/// Resolve an operator-typed backend name against the closed world.
///
/// Refuses an unknown spelling by listing the ones that exist, rather than
/// defaulting to one: silently inspecting a different provider than the one
/// named is a substitution the operator never asked for.
fn backend_by_spelling(spelling: &str) -> Result<ExecBackend> {
    match all_backends().find(|b| b.authored_spelling() == spelling) {
        Some(backend) => Ok(backend),
        None => bail!(
            "unknown execution provider {spelling:?}; this build knows: {}",
            all_backends()
                .map(|b| ExecBackend::authored_spelling(&b))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// What the one certification measured, or why it refused.
#[derive(Debug, Serialize)]
pub struct CertificationReport {
    /// `certified` or the refusal's stable token.
    pub verdict: &'static str,
    /// The measurement, when certified.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub measured: BTreeMap<&'static str, String>,
    /// The refusal sentence, when refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

/// Take (or reuse, it is memoized per process) the one rootless-OCI
/// certification — `certify_youki`, functional probe included.
fn certification_report() -> CertificationReport {
    match kata_worker::oci_runtime::certified_oci_route() {
        Ok(cert) => {
            let measured = BTreeMap::from([
                ("store_path", cert.store_path.display().to_string()),
                ("sha256", cert.sha256.clone()),
                ("version", format!("{:?}", cert.version)),
                ("spec_version", format!("{:?}", cert.spec_version)),
                ("libseccomp_version", cert.libseccomp_version.clone()),
                ("apparmor_profile_loaded", cert.profile.label().to_string()),
                (
                    "apparmor_profile_sha256",
                    cert.installed_profile_sha256.clone(),
                ),
                (
                    "userns_restriction",
                    cert.userns_restriction.label().to_string(),
                ),
                (
                    "delegated_cgroup_parent",
                    cert.delegation
                        .usable_parent
                        .as_ref()
                        .map_or_else(|| "none".to_string(), |p| p.display().to_string()),
                ),
                ("functional_probe_id", cert.functional_probe_id.clone()),
            ]);
            CertificationReport {
                verdict: "certified",
                measured,
                refusal: None,
            }
        }
        Err(refusal) => CertificationReport {
            verdict: refusal.token(),
            measured: BTreeMap::new(),
            refusal: Some(refusal.to_string()),
        },
    }
}

/// Can this host deliver `backend`'s declared containment right now?
///
/// Total over the three build-axis postures, and the arms mean different things:
///
/// * `Unconfined` (`host`) — always deliverable: running with full ambient
///   authority requires nothing of the host.
/// * `UnsupportedInThisBuild` (`oci` on a non-Linux build) — never deliverable, and the
///   refusal is QUOTED from `ExecBackend::unsupported_in_this_build_reason()`.
/// * `CertifiedContainment` (`oci`, the confined backend the capsule route
///   runs) — deliverable iff the one certification certifies. Measured in THIS
///   process: an operator's undelegated shell refuses `delegation_incomplete`,
///   which is the truth about a worker started there.
fn certify_verdict(
    backend: &ExecBackend,
    certification: Option<&CertificationReport>,
) -> Option<String> {
    match backend.provider_posture() {
        ExecProviderPosture::Unconfined => None,
        ExecProviderPosture::UnsupportedInThisBuild => backend.unsupported_in_this_build_reason(),
        ExecProviderPosture::CertifiedContainment => {
            let refused = certification.and_then(|c| c.refusal.as_ref().map(|r| (c.verdict, r)));
            refused.map(|(token, refusal)| {
                format!(
                    "the `{spelling}` containment backend is NOT certified from this process \
                     ({token}): {refusal}",
                    spelling = backend.authored_spelling(),
                )
            })
        }
    }
}

/// Run `kata execution-provider <cmd>`.
///
/// # Errors
/// Propagates rendering failures, an unknown backend spelling, and — for
/// `certify` — the refusal itself, so the shell exit code carries the verdict.
pub fn run_execution_provider_cmd(cmd: ExecutionProviderCmd, format: OutputFormat) -> Result<()> {
    let (report, refusal) = match cmd {
        ExecutionProviderCmd::List => (
            ProviderReport {
                summary_kind: "execution_provider_list",
                providers: all_backends().map(|b| row(&b)).collect(),
                host_containment: None,
                inspected: None,
                certification: None,
                certified: None,
                refusal: None,
            },
            None,
        ),
        ExecutionProviderCmd::Inspect { provider } => {
            let backend = backend_by_spelling(&provider)?;
            (
                ProviderReport {
                    summary_kind: "execution_provider_inspect",
                    providers: vec![row(&backend)],
                    host_containment: Some(kata_worker::sandbox_posture::observe()),
                    inspected: Some(backend.authored_spelling()),
                    certification: None,
                    certified: None,
                    refusal: None,
                },
                None,
            )
        }
        ExecutionProviderCmd::Certify { provider } => {
            let backend = backend_by_spelling(&provider)?;
            let host = kata_worker::sandbox_posture::observe();
            let certification = matches!(
                backend.provider_posture(),
                ExecProviderPosture::CertifiedContainment
            )
            .then(certification_report);
            let refusal = certify_verdict(&backend, certification.as_ref());
            (
                ProviderReport {
                    summary_kind: "execution_provider_certify",
                    providers: vec![row(&backend)],
                    host_containment: Some(host),
                    inspected: Some(backend.authored_spelling()),
                    certification,
                    certified: Some(refusal.is_none()),
                    refusal: refusal.clone(),
                },
                refusal,
            )
        }
    };

    // `--format json` emits the report document bare (a subcommand that
    // ACCEPTS the flag and drops it is the defect class); it is no operation's
    // response, so it carries no `op` tag.
    match format {
        OutputFormat::Json => {
            super::output::emit_record(&report)?;
        }
        OutputFormat::Human => print!("{}", render(&report)),
    }

    // The refusal rides the EXIT CODE, after the report is emitted, so a caller
    // scripting `certify` gets both the machine-readable evidence and a status
    // to branch on. Emitting the report first matters: a refusal an operator
    // cannot see the evidence for is a diagnostic with nothing to act on.
    if let Some(refusal) = refusal {
        bail!("{refusal}");
    }
    Ok(())
}

fn render(report: &ProviderReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "kata {}", report.summary_kind.replace('_', " "));
    let _ = writeln!(out, "\nthis BUILD ships:");
    for provider in &report.providers {
        let _ = writeln!(out, "  [{}] {}", provider.posture, provider.exec);
        let _ = writeln!(out, "      {}", provider.summary);
        if let Some(reason) = provider.unsupported_reason.as_ref() {
            let _ = writeln!(out, "      refusal: {reason}");
        }
    }

    if let Some(host) = report.host_containment.as_ref() {
        let _ = writeln!(
            out,
            "\nthis HOST delivers (measured now): {}",
            host.overall().label()
        );
        for fact in host.facts() {
            let _ = writeln!(out, "  [{}] {}", fact.state.label(), fact.name);
            let _ = writeln!(out, "      {}", fact.evidence);
            for (key, value) in &fact.details {
                let _ = writeln!(out, "        {key}: {value}");
            }
        }

        // The two certificate trichotomies. Rendered beside the facts rather
        // than folded into them: both are statements about what this PROVIDER can
        // do, not observations of whether a hostile stage is confined.
        let _ = writeln!(
            out,
            "\nissuance mediation: {}",
            host.issuance_mediation.label()
        );
        let _ = writeln!(out, "      {}", host.issuance_mediation.evidence());
        let _ = writeln!(out, "stop capability: {}", host.stop_capability.label());
        let _ = writeln!(out, "      {}", host.stop_capability.evidence());

        let _ = writeln!(out, "\nenvironment levers:");
        for switch in &host.kill_switches {
            let _ = writeln!(
                out,
                "  {} = {}",
                switch.env,
                // The direction rides every SET row: this list holds
                // levers that TIGHTEN (a pinned provider address) beside ones that
                // weaken, and an operator scanning for what is wrong must not have
                // to know each lever by heart to tell them apart.
                if switch.set {
                    format!("SET ({}) — {}", switch.direction.label(), switch.effect)
                } else {
                    format!("unset ({})", switch.default_posture)
                }
            );
        }

        // Reported on every inspect, because an operator reading nothing but
        // green would reasonably conclude the containment has no known limit.
        let _ = writeln!(
            out,
            "\nKNOWN CONTAINMENT LIMITS of this build ({}) — true on every host, \
             no operator action clears them:",
            host.known_limits.len()
        );
        for limit in host.known_limits {
            let _ = writeln!(out, "  - {} [{}]", limit.id, limit.owner);
            let _ = writeln!(out, "      {}", limit.statement);
            let _ = writeln!(out, "      basis: {}", limit.basis);
        }
    }

    if let Some(cert) = report.certification.as_ref() {
        let _ = writeln!(
            out,
            "\nthe one certification (functional probe included): {}",
            cert.verdict
        );
        for (key, value) in &cert.measured {
            let _ = writeln!(out, "    {key}: {value}");
        }
        if let Some(refusal) = cert.refusal.as_ref() {
            let _ = writeln!(out, "    {refusal}");
        }
    }

    if let Some(certified) = report.certified {
        let _ = writeln!(
            out,
            "\nverdict: {} for backend \"{}\"",
            if certified { "CERTIFIED" } else { "REFUSED" },
            report.inspected.unwrap_or("?")
        );
        if let Some(refusal) = report.refusal.as_ref() {
            let _ = writeln!(out, "  {refusal}");
        }
    }
    out
}
