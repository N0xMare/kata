//! `kata upgrade` — read-only compatibility preview plus current-format apply
//! validation, run with a NEW binary against a data directory before it is booted.
//! The runtime never migrates a data directory in place.
//!
//! * `kata upgrade --dry-run --data-dir <dir>` (dry-run is the DEFAULT) reports
//!   whether the directory is at this binary's format, WITHOUT touching it, and
//!   previews what boot would refuse or lose on it: the checked programs of
//!   non-terminal executions this binary cannot dispatch, installed workflow packs
//!   that no longer compile, and durable schedules whose target or pinned program
//!   this binary cannot rebind or admit.
//! * `kata upgrade --apply --data-dir <dir>` acquires maintenance authority and
//!   validates the same facts under it; it imports nothing.
//!
//! The format is `operational.db`'s stamp, read through
//! `OperationalDb::refuse_noncurrent_file_schema` by plain file I/O without opening
//! SQLite. A directory at any other stamp is non-current, and the only remediation
//! is a new empty data directory with the old one preserved offline.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kata_core::{ConfigManager, OperationalDb};
use kata_program::execution_program::VerifierStatus;
use kata_program::library::WorkflowLibrary;
use kata_program::preflight::build_workflow_compiled_artifact_from_file;
use kata_workflow::execution_program_store::{
    IncompatibleExecutionProgram, inspect_blocking_incompatible_programs_immutable,
};

use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
use crate::boot::{BLOCKING_PROGRAMS_SCOPE, blocking_programs_recourse, blocking_programs_refusal};
use crate::data_dir_lock::InstalledDataDirLock;

/// `kata upgrade [--data-dir <dir> | --config <path>] [--dry-run | --apply]`.
///
/// `apply == false` is a non-mutating preview (the default). `dry_run` is the
/// explicit opt-in for that default; when neither flag is passed the preview
/// prints an extra nudge toward the explicit form. The data dir is resolved
/// from `--data-dir` first, then `node.data_dir` in `--config`.
pub fn run_upgrade_cmd(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
    apply: bool,
) -> Result<()> {
    run_upgrade_cmd_with_acquirers(
        data_dir,
        config,
        dry_run,
        apply,
        InstalledLifecycleOperationLease::acquire,
        InstalledDiscoveryLease::acquire,
    )
}

fn run_upgrade_cmd_with_acquirers(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
    apply: bool,
    acquire_lifecycle_operation: impl FnOnce() -> Result<InstalledLifecycleOperationLease>,
    acquire_discovery: impl FnOnce() -> Result<InstalledDiscoveryLease>,
) -> Result<()> {
    if apply {
        // Resolve and classify entirely read-only before materializing global
        // coordination inodes. A blocked or unclassifiable apply is
        // observationally read-only, including on a fresh owner account.
        let data_dir = resolve_data_dir(data_dir, config)?;
        preflight_apply(&data_dir)?;

        // Linearize applied maintenance with every installed lifecycle
        // mutation, then exclude the installed main before touching durable
        // state. The same preflight is repeated under these authorities.
        let _operation_lease = acquire_lifecycle_operation().context(
            "upgrade could not serialize against another installed lifecycle or maintenance operation",
        )?;
        let discovery_lease =
            acquire_discovery().context("upgrade requires the installed main to be stopped")?;
        run_apply(&discovery_lease, &data_dir)
    } else {
        let data_dir = resolve_data_dir(data_dir, config)?;
        // `--apply` absent ⇒ preview. `dry_run` distinguishes an explicit
        // `--dry-run` from a bare `kata upgrade` so we can nudge the latter.
        run_dry_run(&data_dir, dry_run)
    }
}

/// Integration-test seam for isolated authority paths. Production callers
/// cannot select these paths because `test-support` is disabled in shipped
/// builds.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn run_upgrade_cmd_with_lease_paths(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
    apply: bool,
    lifecycle_operation_path: &Path,
    discovery_path: &Path,
) -> Result<()> {
    run_upgrade_cmd_with_acquirers(
        data_dir,
        config,
        dry_run,
        apply,
        || InstalledLifecycleOperationLease::acquire_at_for_test(lifecycle_operation_path),
        || InstalledDiscoveryLease::acquire_at_for_test(discovery_path),
    )
}

/// Resolve the data dir: `--data-dir` wins; else read `node.data_dir` from
/// `--config`; else error.
pub fn resolve_data_dir(data_dir: Option<PathBuf>, config: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = data_dir {
        return Ok(dir);
    }
    if let Some(config) = config {
        let mgr = ConfigManager::load(&config)
            .with_context(|| format!("failed to load config at {}", config.display()))?;
        return Ok(mgr.snapshot().node.data_dir.clone());
    }
    bail!(
        "pass --data-dir <dir> (or --config <path> naming node.data_dir) to locate operational.db"
    );
}

/// Report format compatibility without mutating anything. `explicit` is `true`
/// when the operator passed `--dry-run` and `false` for a bare `kata upgrade`
/// (which defaults to this preview) — the bare form gets an extra nudge toward
/// the explicit `--dry-run`/`--apply` forms.
fn run_dry_run(data_dir: &Path, explicit: bool) -> Result<()> {
    run_dry_run_with_post_bind_hook(data_dir, explicit, || Ok(()))
}

fn run_dry_run_with_post_bind_hook(
    data_dir: &Path,
    explicit: bool,
    after_bind: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let data_dir = data_dir.canonicalize().with_context(|| {
        format!(
            "resolving upgrade preview data directory {}",
            data_dir.display()
        )
    })?;
    after_bind()?;
    let operational_path = data_dir.join("operational.db");

    println!("--- kata upgrade (dry run) ---");
    println!("data_dir  = {}", data_dir.display());
    println!("operational.db = {}", operational_path.display());
    println!(
        "target operational schema version = {}",
        kata_core::operational::OPERATIONAL_SCHEMA_VERSION
    );
    // A NEWER binary's directory is an error here, as it is at boot, which
    // refuses it before SQLite is opened.
    kata_core::refuse_newer_operational_schema(&operational_path)
        .with_context(|| format!("failed to scan {}", operational_path.display()))?;

    // The FORMAT first, as `preflight_apply` and boot decide: a directory holding an
    // undeclared database or at another stamp is refused at open whatever state its
    // executions are in, so no set of its programs blocks or unblocks it, and the
    // blocking-programs advice would be false.
    let reason = match classify_durable_format(&data_dir) {
        DurableFormat::Current => {
            let blocking = execution_program_compatibility_plan(&data_dir)?;
            print_execution_program_compatibility_plan(&blocking);
            // Report-only source-pack + schedule-target compat sweep — surfaces at
            // upgrade time the stale packs that otherwise only fail at fire/submit.
            // Never blocks.
            print_installed_artifact_compat_sweep(&data_dir);
            if blocking.is_empty() {
                println!("status = up to date; nothing to migrate.");
            } else {
                println!(
                    "status = blocked; {} incompatible checked program(s) of non-terminal executions; boot refuses this directory for the same programs.",
                    blocking.len()
                );
                println!("scope = {BLOCKING_PROGRAMS_SCOPE}");
                println!("remediation = {}", blocking_programs_recourse(&blocking));
                println!("no changes made (dry run).");
            }
            println!("------------------------------");
            return Ok(());
        }
        DurableFormat::NonCurrent { reason } => reason,
    };

    print_installed_artifact_compat_sweep(&data_dir);
    println!("non-current format detected = {reason}");
    println!("status = non-current format; this binary provides no in-place migration.");
    println!(
        "remediation = initialize a new empty data directory and preserve {} offline.",
        data_dir.display()
    );
    println!("no changes made (dry run).");
    if !explicit {
        println!(
            "(this was a read-only preview — the default. Pass --dry-run to make it explicit.)"
        );
    }
    println!("------------------------------");
    Ok(())
}

/// Validate a clean current-format directory under exclusive maintenance
/// authority. No historical state is migrated in place.
fn run_apply(discovery_lease: &InstalledDiscoveryLease, data_dir: &Path) -> Result<()> {
    run_apply_with_post_lock_hook(discovery_lease, data_dir, || Ok(()))
}

fn run_apply_with_post_lock_hook(
    discovery_lease: &InstalledDiscoveryLease,
    data_dir: &Path,
    after_lock: impl FnOnce() -> Result<()>,
) -> Result<()> {
    // Classify before authority acquisition can write lock metadata. A blocked
    // or unclassifiable program set must make `--apply` observationally
    // read-only.
    preflight_apply(data_dir)?;

    // Upgrade is a writer. It must contend on the exact same kernel-held
    // authority lock as the installed main; PID files are diagnostic state
    // and cannot safely exclude a concurrent process.
    let authority_lock = InstalledDataDirLock::acquire(
        discovery_lease,
        data_dir,
        None,
    )
        .with_context(|| {
            format!(
                "upgrade cannot acquire exclusive installed-main authority for {}; stop the main before applying the upgrade",
                data_dir.display()
            )
        })?;
    after_lock()?;

    // The kernel lock protects the canonical directory captured by the guard,
    // not a possibly retargetable spelling supplied by config or argv. Derive
    // every post-lock read and write from that bound authority.
    let data_dir = authority_lock.data_dir();

    // Re-read under exclusive authority so an execution that transitioned
    // between preflight and lock acquisition cannot escape classification.
    let blocking = preflight_apply(data_dir)?;

    println!("--- kata upgrade (apply) ---");
    println!("data_dir  = {}", data_dir.display());
    println!(
        "operational.db = {}",
        data_dir.join("operational.db").display()
    );
    print_execution_program_compatibility_plan(&blocking);
    // Report-only source-pack + schedule-target compat sweep (same as the preview).
    print_installed_artifact_compat_sweep(data_dir);
    println!("status = clean format is current; no in-place migration is available.");
    println!("----------------------------");
    Ok(())
}

/// Whether a data directory's DURABLE FORMAT is the one this binary writes: no
/// database outside the declared set, and the `operational.db` stamp, as boot reads
/// them.
enum DurableFormat {
    Current,
    NonCurrent { reason: String },
}

fn classify_durable_format(data_dir: &Path) -> DurableFormat {
    let verdict = kata_core::durable_assets::refuse_undeclared_databases(data_dir).and_then(|()| {
        OperationalDb::refuse_noncurrent_file_schema(data_dir.join("operational.db"))
    });
    match verdict {
        Ok(()) => DurableFormat::Current,
        Err(error) => DurableFormat::NonCurrent {
            reason: error.to_string(),
        },
    }
}

fn preflight_apply(data_dir: &Path) -> Result<Vec<IncompatibleExecutionProgram>> {
    if let DurableFormat::NonCurrent { reason } = classify_durable_format(data_dir) {
        bail!(
            "upgrade refused: {reason}. Initialize a new empty data directory and preserve {} \
             offline",
            data_dir.display()
        );
    }
    let blocking = execution_program_compatibility_plan(data_dir)?;
    refuse_blocking_programs(&blocking)?;
    Ok(blocking)
}

/// Refuse the apply while [`execution_program_compatibility_plan`] names any program —
/// in boot's words, because it is boot's set.
fn refuse_blocking_programs(blocking: &[IncompatibleExecutionProgram]) -> Result<()> {
    if blocking.is_empty() {
        return Ok(());
    }
    bail!("upgrade refused: {}", blocking_programs_refusal(blocking))
}

/// The retained checked programs that block this binary on `data_dir` — the SAME set
/// boot's membrane refuses
/// ([`blocking_incompatible_programs`](kata_workflow::execution_program_store::blocking_incompatible_programs):
/// the incompatible programs of executions whose lifecycle is not terminal), read
/// through the shared IMMUTABLE probe — no sidecars, no locks, no ambient journal
/// recovery — so the pre-lock preview stays byte-identical and publishes no
/// coordination.
#[doc(hidden)]
pub fn execution_program_compatibility_plan(
    data_dir: &Path,
) -> Result<Vec<IncompatibleExecutionProgram>> {
    let operational_path = data_dir.join("operational.db");
    inspect_blocking_incompatible_programs_immutable(&operational_path)
        .with_context(|| format!("failed to scan {}", operational_path.display()))
}

fn print_execution_program_compatibility_plan(blocking: &[IncompatibleExecutionProgram]) {
    println!(
        "blocking checked programs (non-terminal executions this binary cannot dispatch) = {}",
        blocking.len()
    );
    for program in blocking {
        println!(
            "  BLOCKED {}: {}",
            program.execution_id,
            program.incompatibility.reason(),
        );
    }
}

// ── Installed-pack / durable-schedule compat sweep (report-only) ─────────────
//
// The store-format classification above (`classify_durable_format` + the incompatible
// checked PROGRAM scan) covers persisted durable state. This sweep covers the OTHER half
// an upgrade changes: the installed workflow-library SOURCE packs and the durable
// schedule targets, which are (re)compiled at fire/submit time under whatever binary is
// running. A pack that stopped compiling under this binary otherwise surfaces only as a
// fire-time log line the operator never sees at upgrade. Surface it here instead.
// Report-only: it never rewrites a pack and never fails the command.

/// What kind of installed artifact a compat finding is about.
#[derive(Clone, Debug, PartialEq, Eq)]
enum InstalledArtifactKind {
    /// An installed workflow-library pack.
    Pack,
    /// A durable schedule whose `submit=` target pack no longer compiles/resolves,
    /// so the next boot reconciliation cannot REBIND it.
    ScheduleTarget { schedule_id: String },
    /// A durable schedule whose PINNED program this binary cannot ADMIT at all — a
    /// program-schema mismatch in `schedules.program_json`.
    ///
    /// # Failure mode
    ///
    /// Strictly worse than [`Self::ScheduleTarget`], which only blocks the rebind: this
    /// schedule fires NOTHING. It self-heals only if the target still compiles (boot
    /// rebinds it); otherwise boot deliberately keeps the stale unfireable pin, and the
    /// sweep's only signal is one WARN per 30s — while the same condition on an
    /// execution program is a fail-closed boot refusal. This finding is the
    /// upgrade-time signal.
    SchedulePin { schedule_id: String },
}

/// One installed-artifact compat finding: a pack (or a schedule's submit target)
/// that no longer compiles/verifies under THIS binary.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InstalledArtifactFinding {
    kind: InstalledArtifactKind,
    /// The library workflow name (or the schedule's `submit=` target name).
    name: String,
    /// The resolved pack source path, when it resolved.
    source: Option<String>,
    /// The full load/verify diagnostic chain (the same message `workflow check`
    /// surfaces).
    diagnostic: String,
}

/// Compile-check every installed library pack and durable schedule target under
/// THIS binary. Reuses the exact `workflow check` compile entrypoint
/// ([`build_workflow_compiled_artifact_from_file`]) — no new compile path. The
/// `library` is injected (production passes [`WorkflowLibrary::default_roots`];
/// tests pass a scoped root); durable schedules are read from the `schedules` table in
/// `<data_dir>/operational.db`, through the IMMUTABLE probe so the preview stays
/// byte-identically read-only.
fn sweep_installed_artifact_compat(
    library: &WorkflowLibrary,
    data_dir: &Path,
) -> Vec<InstalledArtifactFinding> {
    let mut findings = Vec::new();

    // (1) Installed library packs.
    for entry in library.list_effective() {
        match build_workflow_compiled_artifact_from_file(&entry.path, library.roots()) {
            Ok(artifact) => {
                // Compiled, but the checked-program verifier rejects it — surface
                // it too (the same `error` disposition `workflow check` reports).
                if artifact.execution_program.verifier.status == VerifierStatus::Error {
                    findings.push(InstalledArtifactFinding {
                        kind: InstalledArtifactKind::Pack,
                        name: entry.name.clone(),
                        source: Some(entry.path.display().to_string()),
                        diagnostic: format!(
                            "compiles but the checked-program verifier reports {} error diagnostic(s)",
                            artifact
                                .execution_program
                                .verifier
                                .diagnostics
                                .iter()
                                .filter(|d| d.severity
                                    == kata_program::execution_program::VerifierSeverity::Error)
                                .count()
                        ),
                    });
                }
            }
            Err(e) => findings.push(InstalledArtifactFinding {
                kind: InstalledArtifactKind::Pack,
                name: entry.name.clone(),
                source: Some(entry.path.display().to_string()),
                // `{e:#}` renders the full anyhow/KataError chain, so the refusal
                // reaches the operator verbatim, not just the outermost "failed to
                // parse".
                diagnostic: format!("{e:#}"),
            }),
        }
    }

    // (2) Durable schedule targets, read from `operational.db`'s `schedules` table.
    //
    // A schedule does not recompile the pack at fire time — it fires the program
    // PINNED at install — so a stale target does not break the fire. What it breaks
    // is the next boot's ability to REBIND: the schedule keeps running the old pinned
    // program, which is safe but is not what the author now intends.
    //
    // Read through the IMMUTABLE probe, never `OperationalDb::open`: the preview must
    // be observationally read-only, and opening the nucleus applies WAL pragmas,
    // creates the schema, and stamps `user_version` — which materializes `-wal`/`-shm`
    // and fails the preview's own byte-identity regression.
    let operational_path = data_dir.join("operational.db");
    if operational_path.exists() {
        match kata_workflow::schedule::inspect_schedule_targets_immutable(&operational_path) {
            Ok(rows) => {
                for (schedule_id, target) in rows {
                    match library.resolve(&target) {
                        Ok(path) => {
                            if let Err(e) =
                                build_workflow_compiled_artifact_from_file(&path, library.roots())
                            {
                                findings.push(InstalledArtifactFinding {
                                    kind: InstalledArtifactKind::ScheduleTarget { schedule_id },
                                    name: target,
                                    source: Some(path.display().to_string()),
                                    diagnostic: format!("{e:#}"),
                                });
                            }
                        }
                        Err(e) => findings.push(InstalledArtifactFinding {
                            kind: InstalledArtifactKind::ScheduleTarget { schedule_id },
                            name: target,
                            source: None,
                            diagnostic: format!(
                                "submit target no longer resolves in the workflow library: {e}"
                            ),
                        }),
                    }
                }
            }
            Err(e) => findings.push(InstalledArtifactFinding {
                kind: InstalledArtifactKind::ScheduleTarget {
                    schedule_id: "<table>".to_string(),
                },
                name: operational_path.display().to_string(),
                source: None,
                diagnostic: format!("could not read the durable schedule table: {e}"),
            }),
        }
        // (2b) The PINNED program itself, not just the target pack.
        // `schedules.program_json` is a second durable home for checked programs,
        // and neither the `programs` scan above nor `inspect_schedule_targets_immutable`
        // can see it — so without this a schema bump would make a schedule fire
        // nothing forever with no upgrade-time signal at all.
        match kata_workflow::schedule::inspect_incompatible_pinned_programs_immutable(
            &operational_path,
        ) {
            Ok(rows) => {
                for row in rows {
                    findings.push(InstalledArtifactFinding {
                        kind: InstalledArtifactKind::SchedulePin {
                            schedule_id: row.schedule_id,
                        },
                        name: row.submit_pack,
                        source: None,
                        // A DEADLINE, stated as one. The incompatible-PROGRAM scan
                        // above is an upgrade BLOCKER — the operator meets it at the
                        // next `kata serve`, deliberately, with the node refusing to
                        // start. This one blocks nothing: the node starts and the
                        // occurrence is lost unattended at `next_fire_ms`. Reporting
                        // both in the same voice would let a lost 3am fire read
                        // like an advisory.
                        diagnostic: format!(
                            "its PINNED program cannot be admitted by this binary ({}); nothing \
                             refuses the upgrade, but the occurrence due at next_fire_ms={} is \
                             LOST, as is every one after it, until the target compiles and boot \
                             rebinds it",
                            row.reason,
                            row.next_fire_ms.map_or_else(
                                || "<unreadable cursor>".to_string(),
                                |ms| ms.to_string()
                            ),
                        ),
                    });
                }
            }
            Err(e) => findings.push(InstalledArtifactFinding {
                kind: InstalledArtifactKind::SchedulePin {
                    schedule_id: "<table>".to_string(),
                },
                name: operational_path.display().to_string(),
                source: None,
                diagnostic: format!("could not read the durable schedule pins: {e}"),
            }),
        }
    }

    findings
}

/// Print the installed-artifact compat sweep (report-only). Never fails the
/// command.
fn print_installed_artifact_compat_sweep(data_dir: &Path) {
    let library = WorkflowLibrary::default_roots();
    let findings = sweep_installed_artifact_compat(&library, data_dir);
    println!(
        "installed workflow packs / schedule targets that no longer compile = {}",
        findings.len()
    );
    if findings.is_empty() {
        return;
    }
    println!(
        "  report-only: kata does not rewrite a pack. Fix each under the current binary, then \
         re-run `kata check --all`."
    );
    println!(
        "  a SCHEDULE finding does NOT mean the schedule is broken: it fires the program PINNED at \
         install, not a recompile of this target. It means the next boot cannot REBIND it, so the \
         schedule keeps running the program it was last bound to."
    );
    for finding in &findings {
        let label = match &finding.kind {
            InstalledArtifactKind::Pack => "PACK".to_string(),
            InstalledArtifactKind::ScheduleTarget { schedule_id } => {
                format!("SCHEDULE[{schedule_id}]->submit")
            }
            InstalledArtifactKind::SchedulePin { schedule_id } => {
                format!("SCHEDULE-PIN[{schedule_id}] (FIRES NOTHING)")
            }
        };
        let source = finding.source.as_deref().unwrap_or("<unresolved>");
        println!("  {label} {} ({source})", finding.name);
        println!("      {}", finding.diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_dir_lock::{DataDirLock, MainMode};

    /// The blocker must not name an operation no Kata binary has, and must
    /// say the same thing boot says.
    ///
    /// No "retention/prune operation" exists to remove an incompatible row: there
    /// is no `kata prune` subcommand, no API route prunes, and every primitive
    /// that physically deletes a program row is `cfg(test)` / `test-support` only.
    ///
    /// The preview and boot must agree on whether finishing the runs clears the
    /// block, so a preview may not block on terminal programs boot never checks.
    /// Both compute one set — the programs of NON-terminal executions — and render it
    /// through `boot::blocking_programs_refusal`, so finishing or cancelling the
    /// executions is a recourse that works, and both say so.
    ///
    /// The blocker here is a CURRENT-schema program (bytes that do not decode), the
    /// one kind a binary that opens this directory wrote. A schema verdict has no such
    /// binary; `a_schema_verdict_blocker_is_offered_no_writing_binary` holds that half.
    #[test]
    fn the_incompatible_program_refusal_names_only_recourse_that_exists() {
        let blocked = vec![undecodable_current_schema_blocker()];

        let err = refuse_blocking_programs(&blocked)
            .expect_err("a non-terminal incompatible row must refuse the upgrade");
        let message = err.to_string();

        assert!(
            !message.contains("retention/prune operation"),
            "the refusal must not name an operation that exists nowhere: {message}"
        );
        assert!(
            message.contains("NO Kata binary has an operation that removes a checked-program row"),
            "it must say so outright, so nobody spends an afternoon in `kata --help`: {message}"
        );
        assert!(
            message.contains("Finishing or cancelling these executions with the binary that wrote them clears this refusal"),
            "a terminal execution's program blocks nothing, so finishing is a recourse: {message}"
        );
        assert!(
            !message.contains("does not clear"),
            "and nothing may still say the opposite: {message}"
        );
        assert!(
            message.contains("with the Kata binary that wrote these programs"),
            "supported move 1 names the writing binary: {message}"
        );
        assert!(
            message.contains("`[node] data_dir`"),
            "supported move 2, named as the config key an operator edits: {message}"
        );
        assert!(
            message.contains("kata init"),
            "with a command that exists: {message}"
        );
        assert_eq!(
            message.strip_prefix("upgrade refused: "),
            Some(blocking_programs_refusal(&blocked).as_str()),
            "the upgrade refusal is boot's sentence about the same set: {message}"
        );

        // And the empty case still passes, so the refusal is not unconditional.
        refuse_blocking_programs(&[]).expect("no blocked rows, no refusal");
    }

    fn undecodable_current_schema_blocker() -> IncompatibleExecutionProgram {
        use kata_workflow::execution_program_store::{
            CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionProgramIncompatibility,
        };
        IncompatibleExecutionProgram {
            execution_id: ulid::Ulid::from_parts(1, 1),
            schema_version: Some(u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION)),
            incompatibility: ExecutionProgramIncompatibility::UndecodableCurrentSchema {
                detail: "missing field `stages`".to_string(),
            },
        }
    }

    fn legacy_schema_blocker() -> IncompatibleExecutionProgram {
        use kata_workflow::execution_program_store::ExecutionProgramIncompatibility;
        IncompatibleExecutionProgram {
            execution_id: ulid::Ulid::from_parts(2, 2),
            schema_version: Some(2),
            incompatibility: ExecutionProgramIncompatibility::LegacySchema { version: 2 },
        }
    }

    /// A program whose header names another checked-program schema was written by no
    /// binary that opens this directory: every checked-program schema bump moves the
    /// operational stamp, and a directory at another stamp is refused before this check.
    /// So the refusal about it may not, anywhere in the sentence, send the operator to
    /// finish or cancel the execution on the binary that wrote it — the per-program
    /// reason already says nothing can dispatch it here, and a scope or recourse that
    /// said otherwise would contradict it. The one move is the fresh data directory.
    #[test]
    fn a_schema_verdict_blocker_is_offered_no_writing_binary() {
        let blocked = vec![legacy_schema_blocker()];
        let message = refuse_blocking_programs(&blocked)
            .expect_err("a non-terminal legacy-schema row must refuse the upgrade")
            .to_string();
        let lowered = message.to_lowercase();
        for offer in [
            "finish",
            "cancel",
            "binary that wrote",
            "can still dispatch",
        ] {
            assert!(
                !lowered.contains(offer),
                "no binary that opens this directory wrote this program ({offer:?}): {message}"
            );
        }
        assert!(
            message.contains("`[node] data_dir`") && message.contains("kata init"),
            "the move that exists, named as the key an operator edits: {message}"
        );
        assert!(
            message.contains("NO Kata binary has an operation that removes a checked-program row"),
            "and the non-existent removal is still ruled out: {message}"
        );
        assert_eq!(
            blocking_programs_recourse(&blocked),
            message
                .rsplit_once(BLOCKING_PROGRAMS_SCOPE)
                .map(|(_, recourse)| recourse.trim_start().to_string())
                .expect("the refusal carries the scope, then the recourse"),
            "the dry-run's `remediation =` line is the refusal's own recourse"
        );
    }

    /// Beside a program its writer can still dispatch, the writing-binary move is
    /// offered — and scoped to such programs, because the schema-verdict one in the same
    /// set still has no writer.
    #[test]
    fn a_mixed_blocking_set_scopes_the_writing_binary_move_to_current_schema_programs() {
        let blocked = vec![
            undecodable_current_schema_blocker(),
            legacy_schema_blocker(),
        ];
        let message = refuse_blocking_programs(&blocked)
            .expect_err("both rows block")
            .to_string();
        assert!(
            message.contains("with the Kata binary that wrote these programs"),
            "the current-schema program keeps its writing-binary move: {message}"
        );
        assert!(
            message.contains("only for a program at this binary's checked-program schema"),
            "and the move says which programs it covers: {message}"
        );
    }

    /// The report-only compat sweep flags an installed pack that no longer compiles
    /// under this binary AND a durable schedule whose `submit=` target is that stale
    /// pack — surfacing at upgrade time what would otherwise be discovered at the
    /// next boot's rebind. A compiling pack and a schedule pointing at it are NOT
    /// flagged.
    ///
    /// The schedules are read from `operational.db`'s `schedules` table, and the fixture PINS
    /// a real compiled program per schedule because the durable row cannot exist
    /// without one — which is also why a stale target breaks only the next rebind,
    /// not the fire.
    #[test]
    fn compat_sweep_flags_stale_pack_and_schedule_target() {
        use kata_program::schedule::ScheduleSpec;
        use kata_program::schedule::ScheduleTrigger;
        use kata_workflow::schedule::ScheduleFace;

        let lib_root = tempfile::tempdir().unwrap();
        // Compiles clean under this binary.
        std::fs::write(
            lib_root.path().join("good-pack.star"),
            "s = stage(id = \"s\", prompt = \"do\", agent = \"codex\")\n\
             workflow(\"good-pack\", root = [s])\n",
        )
        .unwrap();
        // No longer compiles: its root names a stage nothing defines.
        std::fs::write(
            lib_root.path().join("stale-pack.star"),
            "s = stage(id = \"s\", prompt = \"do\", agent = \"codex\")\n\
             workflow(\"stale-pack\", root = [undefined_stage])\n",
        )
        .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        // The pinned program is deliberately NOT the stale source: a schedule's pin is
        // whatever compiled at install time, and the stale source is what no longer
        // compiles NOW. That is exactly the shape the finding reports.
        let pinned = kata_program::execution_program::compile_starlark_execution_program(
            "s = stage(id = \"s\", prompt = \"do\", agent = \"codex\")\n\
             workflow(\"good-pack\", root = [s])\n",
            "good-pack.star",
            &[],
        )
        .unwrap();
        {
            let face = ScheduleFace::new(std::sync::Arc::new(
                kata_core::OperationalDb::open(data_dir.path().join("operational.db")).unwrap(),
            ));
            for (id, pack) in [
                ("nightly-stale", "stale-pack"),
                ("nightly-good", "good-pack"),
            ] {
                face.install(
                    &ScheduleSpec {
                        id: id.into(),
                        submit_pack: pack.into(),
                        trigger: ScheduleTrigger::Interval { every_ms: 60_000 },
                        on_missed: kata_program::schedule::MissedPolicy::default(),
                        params: serde_json::Map::new(),
                    },
                    &pinned,
                    0,
                )
                .unwrap();
            }
        }

        let library = WorkflowLibrary::new(vec![lib_root.path().to_path_buf()]);
        let findings = sweep_installed_artifact_compat(&library, data_dir.path());

        // The stale PACK is flagged, carrying the compile diagnostic verbatim.
        let pack = findings
            .iter()
            .find(|f| f.kind == InstalledArtifactKind::Pack)
            .expect("stale pack must be flagged");
        assert_eq!(pack.name, "stale-pack");
        assert!(
            pack.diagnostic.contains("undefined_stage"),
            "pack finding must carry the compile diagnostic: {}",
            pack.diagnostic
        );

        // The stale SCHEDULE TARGET is flagged; the good one is not.
        let flagged_stale = findings.iter().any(|f| {
            matches!(&f.kind, InstalledArtifactKind::ScheduleTarget { schedule_id }
                if schedule_id == "nightly-stale")
                && f.name == "stale-pack"
        });
        assert!(
            flagged_stale,
            "stale schedule target must be flagged: {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| matches!(&f.kind,
                InstalledArtifactKind::ScheduleTarget { schedule_id } if schedule_id == "nightly-good")),
            "a schedule pointing at a compiling pack must NOT be flagged: {findings:?}"
        );

        // The good pack is never flagged.
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == InstalledArtifactKind::Pack && f.name == "good-pack"),
            "a compiling pack must not be flagged: {findings:?}"
        );
    }

    /// A directory an older binary wrote is non-current by its `operational.db`
    /// stamp, and `--apply`'s preflight refuses it with the fresh-directory recourse.
    /// The same directory with a current stamp is current, so the refusal is the
    /// stamp's.
    #[test]
    fn a_directory_an_older_binary_wrote_is_refused_by_its_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let operational = dir.path().join("operational.db");
        let behind = kata_core::operational::OPERATIONAL_SCHEMA_VERSION - 1;
        OperationalDb::open(&operational)
            .unwrap()
            .debug_stamp_user_version(behind)
            .unwrap();

        let DurableFormat::NonCurrent { reason } = classify_durable_format(dir.path()) else {
            panic!("a behind stamp must classify the directory as non-current");
        };
        assert!(
            reason.contains(&format!("schema version {behind} is not the clean runtime")),
            "{reason}"
        );
        let refusal = preflight_apply(dir.path())
            .expect_err("apply must refuse a non-current directory")
            .to_string();
        assert!(
            refusal.contains("Initialize a new empty data directory"),
            "{refusal}"
        );

        rusqlite::Connection::open(&operational)
            .unwrap()
            .pragma_update(
                None,
                "user_version",
                kata_core::operational::OPERATIONAL_SCHEMA_VERSION,
            )
            .unwrap();
        assert!(matches!(
            classify_durable_format(dir.path()),
            DurableFormat::Current
        ));
    }

    /// A CURRENT-stamped directory that holds a database no durable-asset row declares
    /// is non-current to the preview and refused by `--apply`'s preflight, as boot
    /// refuses it; the same directory without that file is current, so the refusal is
    /// the file's.
    #[test]
    fn a_current_directory_holding_an_undeclared_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        drop(OperationalDb::open(dir.path().join("operational.db")).unwrap());
        let undeclared = dir.path().join("ledger.db");
        std::fs::write(&undeclared, b"a database this binary does not declare").unwrap();

        let DurableFormat::NonCurrent { reason } = classify_durable_format(dir.path()) else {
            panic!("an undeclared database must classify the directory as non-current");
        };
        assert!(reason.contains("ledger.db"), "{reason}");
        let refusal = preflight_apply(dir.path())
            .expect_err("apply must refuse a directory holding an undeclared database")
            .to_string();
        assert!(
            refusal.contains("Initialize a new empty data directory"),
            "{refusal}"
        );

        std::fs::remove_file(&undeclared).unwrap();
        assert!(matches!(
            classify_durable_format(dir.path()),
            DurableFormat::Current
        ));
    }

    /// A clean library with no stale packs and no durable schedules yields an empty
    /// sweep — the report-only path is silent when nothing is wrong.
    #[test]
    fn compat_sweep_is_empty_for_a_clean_library() {
        let lib_root = tempfile::tempdir().unwrap();
        std::fs::write(
            lib_root.path().join("ok.star"),
            "s = stage(id = \"s\", prompt = \"do\", agent = \"codex\")\n\
             workflow(\"ok\", root = [s])\n",
        )
        .unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let library = WorkflowLibrary::new(vec![lib_root.path().to_path_buf()]);
        assert!(sweep_installed_artifact_compat(&library, data_dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_stays_on_one_physical_source_after_parent_alias_retarget() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let first_parent = root.path().join("first");
        let second_parent = root.path().join("second");
        let first_data = first_parent.join("data");
        let second_data = second_parent.join("data");
        std::fs::create_dir_all(&first_data).unwrap();
        std::fs::create_dir_all(&second_data).unwrap();
        // A CURRENT-FORMAT source and a NON-current one, so the preview has something
        // real to classify on either side of the alias retarget.
        drop(OperationalDb::open(first_data.join("operational.db")).unwrap());
        std::fs::write(second_data.join("operational.db"), b"not sqlite").unwrap();

        let alias = root.path().join("selected");
        symlink(&first_parent, &alias).unwrap();
        run_dry_run_with_post_bind_hook(&alias.join("data"), true, || {
            std::fs::remove_file(&alias)?;
            symlink(&second_parent, &alias)?;
            Ok(())
        })
        .expect("upgrade preview remains bound to the canonical source it classified");
    }

    #[cfg(unix)]
    #[test]
    fn apply_stays_bound_to_the_locked_directory_after_parent_alias_retarget() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let first_parent = root.path().join("first");
        let second_parent = root.path().join("second");
        let first_data = first_parent.join("data");
        let second_data = second_parent.join("data");
        std::fs::create_dir_all(&first_data).unwrap();
        std::fs::create_dir_all(&second_data).unwrap();
        drop(DataDirLock::acquire(&first_data, MainMode::Installed, None).unwrap());
        drop(DataDirLock::acquire(&second_data, MainMode::Installed, None).unwrap());
        let second_lock_before = std::fs::read(second_data.join("main.lock")).unwrap();

        let alias = root.path().join("selected");
        symlink(&first_parent, &alias).unwrap();
        let configured_data = alias.join("data");
        let discovery = InstalledDiscoveryLease::acquire_at_for_test(
            &root.path().join("coordination/discovery.lock"),
        )
        .unwrap();

        run_apply_with_post_lock_hook(&discovery, &configured_data, || {
            std::fs::remove_file(&alias)?;
            symlink(&second_parent, &alias)?;
            Ok(())
        })
        .expect("upgrade must continue through the canonical directory protected by its lock");

        assert_eq!(
            std::fs::read(second_data.join("main.lock")).unwrap(),
            second_lock_before,
            "retargeted alias must not receive post-lock metadata"
        );
    }

    #[test]
    fn apply_refuses_while_a_node_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let coordination = tempfile::tempdir().unwrap();
        let lease_parent = coordination.path().join("coordination");
        drop(DataDirLock::acquire(dir.path(), MainMode::Installed, None).unwrap());
        drop(OperationalDb::open(dir.path().join("operational.db")).unwrap());
        let _main = DataDirLock::acquire(dir.path(), MainMode::Installed, None)
            .expect("simulate installed main holding authority");

        let error = run_upgrade_cmd_with_lease_paths(
            Some(dir.path().to_path_buf()),
            None,
            false,
            true,
            &lease_parent.join("lifecycle-operation.lock"),
            &lease_parent.join("discovery.lock"),
        )
        .expect_err("apply must refuse while a node is live against the dir");
        let message = error.to_string();
        assert!(
            message.contains("already locked") || message.contains("stop the main"),
            "the refusal must explain that the main holds authority, got: {message}"
        );
    }

    #[test]
    fn apply_refuses_a_concurrent_installed_lifecycle_operation() {
        let dir = tempfile::tempdir().unwrap();
        let coordination = tempfile::tempdir().unwrap();
        let lease_parent = coordination.path().join("coordination");
        let lifecycle_path = lease_parent.join("lifecycle-operation.lock");
        let discovery_path = lease_parent.join("discovery.lock");
        drop(OperationalDb::open(dir.path().join("operational.db")).unwrap());
        let _held = InstalledLifecycleOperationLease::acquire_at_for_test(&lifecycle_path)
            .expect("hold installed lifecycle mutation authority");

        let error = run_upgrade_cmd_with_lease_paths(
            Some(dir.path().to_path_buf()),
            None,
            false,
            true,
            &lifecycle_path,
            &discovery_path,
        )
        .expect_err("upgrade must serialize with every installed lifecycle mutation");
        assert!(
            format!("{error:#}")
                .contains("another Kata installed lifecycle or maintenance operation"),
            "unexpected lifecycle contention diagnostic: {error:#}"
        );
        assert!(
            !discovery_path.exists(),
            "lock order must refuse on lifecycle authority before creating discovery"
        );
    }
}
