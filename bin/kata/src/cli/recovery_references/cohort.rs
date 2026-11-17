use super::{
    BTreeMap, BTreeSet, BackupManifest, Instant, KataResult, MAX_RECORD_BYTES, Path, STORES_SUBDIR,
    census, open, refuse_noncurrent_program_schema, refused, sql,
};
use kata_core::store::backup::RecoverySleepCheckpoint;
use ulid::Ulid;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecoveryExecutionBoundary {
    pub program_hash: String,
    pub sleeps: Vec<RecoverySleepCheckpoint>,
    pub agent_labels: BTreeSet<String>,
    pub requires_default_agent: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecoveryCohort {
    pub authority_head: u64,
    pub executions: BTreeMap<Ulid, RecoveryExecutionBoundary>,
}

impl RecoveryCohort {
    pub(crate) fn verify_target_agents(&self, config: &kata_types::KataConfig) -> KataResult<()> {
        if self.executions.is_empty() {
            return Ok(());
        }
        if config.agents.is_empty() {
            return Err(refused(
                "checkpoint target requires an explicit agent configuration; implicit backend fallback is not a verified recovery binding",
            ));
        }
        if !config.workers.transports.iter().any(|transport| {
            matches!(
                transport,
                kata_types::config::WorkerTransportConfig::SupervisedNode {}
            )
        }) {
            return Err(refused(
                "checkpoint continuation currently requires a supervised node and the jj execution workspace provider; future external-worker capabilities are not a verified binding",
            ));
        }
        for execution in self.executions.values() {
            for label in &execution.agent_labels {
                if !matches!(label.as_str(), "shell" | "workspace_effect")
                    && !config.agents.contains_key(label)
                {
                    return Err(refused(&format!(
                        "checkpoint frozen program requires unconfigured target agent label {label}"
                    )));
                }
            }
            if execution.requires_default_agent
                && !config.agents.contains_key("default")
                && config.agents.len() != 1
            {
                return Err(refused(
                    "checkpoint Any-agent routing requires an explicit configured default or one configured operator-selected backend",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn verify_checkpoints(
        &self,
        checkpoints: &[kata_core::store::backup::RecoveryWorkspaceCheckpoint],
    ) -> KataResult<()> {
        if checkpoints.len() != self.executions.len() {
            return Err(refused(
                "checkpoint population differs from captured execution authority",
            ));
        }
        let mut seen = BTreeSet::new();
        for checkpoint in checkpoints {
            let boundary = self
                .executions
                .get(&checkpoint.execution_id)
                .ok_or_else(|| refused("checkpoint names an unsupported execution"))?;
            if !seen.insert(checkpoint.execution_id)
                || checkpoint.authority_head != self.authority_head
                || checkpoint.program_hash != boundary.program_hash
                || checkpoint.sleeps != boundary.sleeps
            {
                return Err(refused(
                    "checkpoint does not match the exact captured program and sleep fences",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn recovery_cohort_source(
    data_dir: &Path,
    deadline: Instant,
) -> KataResult<RecoveryCohort> {
    inspect(data_dir, CohortContext::Source, deadline)
}

pub(crate) fn recovery_cohort_target(
    data_dir: &Path,
    deadline: Instant,
) -> KataResult<RecoveryCohort> {
    inspect(data_dir, CohortContext::TargetReadiness, deadline)
}

pub(crate) fn recovery_cohort_captured(
    artifact: &Path,
    manifest: &BackupManifest,
    deadline: Instant,
) -> KataResult<RecoveryCohort> {
    // ONE required database. This inspection reads `operational.db` alone, so requiring
    // another would refuse an artifact over a store this inspection never reads.
    if !manifest
        .databases
        .iter()
        .any(|item| item == "operational.db")
    {
        return Err(refused("missing captured cohort authority"));
    }
    inspect(
        &artifact.join(STORES_SUBDIR),
        CohortContext::Captured,
        deadline,
    )
}

enum CohortContext {
    Source,
    Captured,
    TargetReadiness,
}

#[cfg(test)]
#[path = "cohort_tests.rs"]
mod authority_tests;

fn inspect(
    directory: &Path,
    context: CohortContext,
    deadline: Instant,
) -> KataResult<RecoveryCohort> {
    let immutable = matches!(context, CohortContext::Captured);
    let (_file, connection) = open(&directory.join("operational.db"), immutable)?;
    connection.execute_batch("BEGIN").map_err(sql)?;
    let population =
        kata_core::operational::inspect_recovery_sleep_population(&connection, deadline)?;
    if population.has_pending_imports && !matches!(context, CohortContext::TargetReadiness) {
        return Err(refused(
            "source retains unreleased import quarantine; complete its original reconciliation before taking another recoverable backup",
        ));
    }
    let mut cohort = RecoveryCohort {
        authority_head: population.authority_head,
        executions: BTreeMap::new(),
    };
    for (execution, sleeps) in population.executions {
        if Instant::now() >= deadline {
            return Err(refused("cohort deadline elapsed"));
        }
        let (bound_hash, bytes): (Vec<u8>, Option<Vec<u8>>) = connection.query_row(
            &format!("SELECT program_hash,CASE WHEN length(program_json)<={MAX_RECORD_BYTES} THEN program_json END FROM programs WHERE execution_id=?1"),
            [execution.to_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?)),
        ).map_err(sql)?;
        let bytes = bytes.ok_or_else(|| refused("checkpoint program exceeds decode bound"))?;
        refuse_noncurrent_program_schema(&bytes)?;
        let program: kata_program::execution_program::ExecutionProgram =
            serde_json::from_slice(&bytes).map_err(|_| refused("invalid checkpoint program"))?;
        if program.schema_version
            != kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION
            || !program.summary.worktree_isolated
            || program.program_hash.as_bytes() != bound_hash
            || kata_program::execution_program::rederive_program_hash(&program)
                != program.program_hash
        {
            return Err(refused(
                "checkpoint requires the original checked isolated program",
            ));
        }
        program
            .validate_carried_stage_execution_classes()
            .map_err(|_| refused("invalid checkpoint stage classes"))?;
        for sleep in &sleeps {
            let id = program
                .checked_stage_id_for_runtime_stage(&sleep.stage_id)
                .ok_or_else(|| refused("sleep stage absent from frozen program"))?;
            let stage = program
                .stages
                .get(&id)
                .ok_or_else(|| refused("checked sleep stage missing"))?;
            if stage.durable_sleep.is_none() {
                return Err(refused("parked attempt is not a checked durable sleep"));
            }
            // A durable sleep parks on the main-side wait plane now — the attempt
            // row exists only to bind the park to its stage, and the stage's
            // `durable_sleep` check above is the whole authority this census
            // needs from it. A capsule frame carries no checked dispatch kind to
            // cross-check; the stage table already proved the stage IS a
            // declared durable sleep.
            let stage_bound: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM attempts WHERE attempt_id=?1 AND stage_id=?2",
                    rusqlite::params![
                        sleep.attempt_id.to_bytes().as_slice(),
                        stage.stage_id.0.as_str(),
                    ],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            if stage_bound == 0 {
                return Err(refused(
                    "checkpoint sleep attempt is not bound to its checked sleep stage",
                ));
            }
        }
        let (agent_labels, requires_default_agent) = declared_agent_labels(&program);
        cohort.executions.insert(
            execution,
            RecoveryExecutionBoundary {
                program_hash: program.program_hash.to_string(),
                sleeps,
                agent_labels,
                requires_default_agent,
            },
        );
    }
    let census = census(directory, immutable, deadline)?;
    let mut covered = census.durable_candidates;
    covered.extend(cohort.executions.keys().map(|id| id.to_bytes().to_vec()));
    if !census.isolated_executions.is_subset(&covered) {
        return Err(refused(
            "isolated execution lacks a terminal receipt or supported sleep checkpoint",
        ));
    }
    Ok(cohort)
}

fn declared_agent_labels(
    program: &kata_program::execution_program::ExecutionProgram,
) -> (BTreeSet<String>, bool) {
    let mut labels = BTreeSet::new();
    let mut requires_default = false;
    for stage in program.stages.values() {
        if let Some(label) = &stage.op.agent_label {
            labels.insert(label.to_string());
        } else {
            requires_default = true;
        }
        labels.extend(stage.op.agent_panel.iter().map(ToString::to_string));
        labels.extend(
            stage
                .invocation_envelope
                .children
                .iter()
                .filter_map(|child| child.agent.as_ref())
                .map(ToString::to_string),
        );
    }
    (labels, requires_default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_core::store::backup::{RecoveryCheckpointTree, RecoveryWorkspaceCheckpoint};

    #[test]
    fn checkpoint_target_requires_declared_local_agent_labels_without_future_worker_guesses() {
        let mut config: kata_types::KataConfig = toml::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/kata.example.toml"
        )))
        .unwrap();
        config.workers.transports =
            vec![kata_types::config::WorkerTransportConfig::SupervisedNode {}];
        config.agents.clear();
        let agent = kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: None,
            credential: None,
            env: BTreeMap::new(),
        };
        config
            .agents
            .insert("operator-selected".into(), agent.clone());
        let execution = Ulid::new();
        let mut cohort = RecoveryCohort {
            authority_head: 1,
            executions: BTreeMap::from([(
                execution,
                RecoveryExecutionBoundary {
                    program_hash: "a".repeat(64),
                    sleeps: vec![],
                    agent_labels: BTreeSet::from(["shell".into(), "workspace_effect".into()]),
                    requires_default_agent: false,
                },
            )]),
        };
        cohort.verify_target_agents(&config).unwrap();
        cohort
            .executions
            .get_mut(&execution)
            .unwrap()
            .agent_labels
            .insert("missing-panel-member".into());
        assert!(cohort.verify_target_agents(&config).is_err());
        config.agents.insert("missing-panel-member".into(), agent);
        cohort.verify_target_agents(&config).unwrap();
        cohort
            .executions
            .get_mut(&execution)
            .unwrap()
            .requires_default_agent = true;
        assert!(
            cohort.verify_target_agents(&config).is_err(),
            "ambiguous Any choice must refuse"
        );
        config.agents.remove("operator-selected");
        cohort.verify_target_agents(&config).unwrap();
        let configured = std::mem::take(&mut config.agents);
        assert!(
            cohort.verify_target_agents(&config).is_err(),
            "empty configuration must not activate an implicit backend"
        );
        config.agents = configured;
        config.workers.transports = vec![];
        assert!(
            cohort.verify_target_agents(&config).is_err(),
            "future external capacity is not target proof"
        );
        cohort.executions.clear();
        cohort.verify_target_agents(&config).unwrap();
    }

    #[test]
    fn checkpoint_binding_refuses_changed_cut_program_attempt_and_deadline() {
        let execution = Ulid::new();
        let sleep = RecoverySleepCheckpoint {
            attempt_id: Ulid::new(),
            stage_id: "nap".into(),
            attempt_ordinal: 0,
            lease_epoch: 0,
            wait_deadline_ms: 10_000,
            transition_seq: 3,
        };
        let cohort = RecoveryCohort {
            authority_head: 4,
            executions: BTreeMap::from([(
                execution,
                RecoveryExecutionBoundary {
                    program_hash: "a".repeat(64),
                    sleeps: vec![sleep.clone()],
                    agent_labels: BTreeSet::new(),
                    requires_default_agent: false,
                },
            )]),
        };
        let checkpoint = RecoveryWorkspaceCheckpoint {
            execution_id: execution,
            program_hash: "a".repeat(64),
            authority_head: 4,
            sleeps: vec![sleep],
            workspace_commit_id: "b".repeat(40),
            candidate: RecoveryCheckpointTree {
                root_mode: 0o700,
                entries: vec![],
                digest: "c".repeat(64),
            },
        };
        cohort
            .verify_checkpoints(std::slice::from_ref(&checkpoint))
            .unwrap();
        assert!(cohort.verify_checkpoints(&[]).is_err());
        assert!(
            cohort
                .verify_checkpoints(&[checkpoint.clone(), checkpoint.clone()])
                .is_err()
        );
        for variant in 0..7 {
            let mut changed = checkpoint.clone();
            match variant {
                0 => changed.authority_head += 1,
                1 => changed.program_hash = "d".repeat(64),
                2 => changed.sleeps[0].attempt_id = Ulid::new(),
                3 => changed.sleeps[0].wait_deadline_ms += 1,
                4 => changed.sleeps[0].transition_seq += 1,
                5 => changed.sleeps[0].lease_epoch += 1,
                _ => changed.execution_id = Ulid::new(),
            }
            assert!(
                cohort.verify_checkpoints(&[changed]).is_err(),
                "mutation {variant}"
            );
        }
    }
}
