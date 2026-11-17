//! Shared subcommand enums and value types for the Kata CLI.
//!
//! All clap-derived `Subcommand` enums live here so the dispatch
//! site (`cli::run`) can see the full surface in one import. The
//! per-handler `run_*` functions live in focused sibling modules such as
//! `workflows`, `service`, `solo`, and `config_check`.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

/// Offline evidence-packet commands for reviewing preserved proof artifacts.
#[derive(Debug, Subcommand)]
pub enum EvidenceCmd {
    /// Summarize one evidence packet directory or JSON evidence file.
    Summary {
        /// Evidence packet directory, `evidence-summary.json`, or `*-evidence.json` file.
        path: PathBuf,
        /// Emit a machine-readable JSON summary.
        #[arg(long)]
        json: bool,
        /// Exit nonzero unless the evidence packet has a passing status.
        #[arg(long)]
        strict: bool,
    },
    /// List evidence packets under a directory.
    List {
        /// Root directory to scan for evidence packet summaries.
        path: PathBuf,
        /// Emit a machine-readable JSON list.
        #[arg(long)]
        json: bool,
        /// Exit nonzero if any discovered packet is not passing.
        #[arg(long)]
        strict: bool,
    },
}

/// Steering/evidence commands backed by the running Kata API node.
#[derive(Debug, Subcommand)]
pub enum SteerCmd {
    /// List human-request evidence rows across executions.
    HumanRequests {
        /// Restrict rows to one execution id.
        #[arg(long)]
        execution_id: Option<String>,
        /// Restrict rows to an exact request status.
        #[arg(long, conflicts_with_all = ["answered", "unanswered"])]
        status: Option<String>,
        /// Restrict rows to answered requests.
        #[arg(long, conflicts_with = "unanswered")]
        answered: bool,
        /// Restrict rows to requests still using their default assumption.
        #[arg(long, conflicts_with = "answered")]
        unanswered: bool,
    },
    /// Answer one human-request row by exact request id, resuming it if blocking.
    AnswerHumanRequest {
        /// Execution id that owns the human-request row.
        execution_id: String,
        /// Exact request id from replay/watch `human_requests[]`.
        request_id: String,
        /// Compact answer summary to persist on the row.
        answer_summary: String,
        /// Optional external steering row id that supplied this answer.
        #[arg(long)]
        steering_id: Option<u64>,
    },
    /// List external input evidence rows across executions.
    ExternalInputs {
        /// Restrict rows to one execution id.
        #[arg(long)]
        execution_id: Option<String>,
        /// Restrict rows to one channel id.
        #[arg(long)]
        channel: Option<String>,
    },
    /// Append one checked external-input row for prompt/context consumption.
    AppendExternalInput {
        /// Execution id that owns the declared external-input channel.
        execution_id: String,
        /// Declared external-input channel id.
        channel: String,
        /// Text to expose to stages through `external_inputs`.
        text: String,
        /// Optional stable input id. Omitted means the server mints one.
        #[arg(long)]
        input_id: Option<String>,
        /// Optional source label, e.g. operator, a CI system, or a webhook.
        #[arg(long)]
        source: Option<String>,
        /// Optional target stage. Defaults to the channel's declared stage.
        #[arg(long)]
        target_stage: Option<String>,
        /// Optional JSON payload string to carry alongside text.
        #[arg(long)]
        payload_json: Option<String>,
    },
}

/// Native memory/context commands backed by the running Kata API node.
#[derive(Debug, Subcommand)]
pub enum MemoryCmd {
    /// Print a read-only memory snapshot, optionally filtered by kind/status.
    Snapshot {
        /// Restrict the snapshot to one memory kind, e.g. task or decision.
        #[arg(long, conflicts_with = "kinds")]
        kind: Option<String>,
        /// Restrict the snapshot to a comma-separated set of memory kinds.
        #[arg(long)]
        kinds: Option<String>,
        /// Restrict the snapshot to one status, e.g. active or proposed.
        #[arg(long, conflicts_with = "statuses")]
        status: Option<String>,
        /// Restrict the snapshot to a comma-separated set of statuses.
        #[arg(long)]
        statuses: Option<String>,
        /// Restrict the snapshot with the same text query used by memory selectors.
        #[arg(long)]
        query: Option<String>,
        /// Maximum number of objects to return.
        #[arg(long)]
        limit: Option<u32>,
        /// Also write a filesystem projection rooted at this directory.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Print one memory object by id.
    Get {
        /// Memory object id.
        id: String,
    },
    /// Apply one proposal JSON file.
    Propose {
        /// Path to a JSON-serialized MemoryProposal.
        #[arg(long)]
        file: PathBuf,
    },
    /// Apply every proposal JSON file in a filesystem inbox directory.
    ImportInbox {
        /// Directory containing proposal JSON files.
        #[arg(long, default_value = ".kata/memory/inbox")]
        dir: PathBuf,
        /// Move processed JSON files out of the inbox.
        #[arg(long, conflicts_with = "delete_processed")]
        archive_dir: Option<PathBuf>,
        /// Delete applied or conflicted JSON files after import.
        #[arg(long)]
        delete_processed: bool,
    },
}

/// Product-facing controller commands for autonomous factory workflows.
#[derive(Debug, Subcommand)]
pub enum FactoryCmd {
    /// Submit a factory workflow to the running Kata API node.
    Run {
        /// Workflow library name or path to a `.star` workflow file.
        workflow: String,
        /// Submit the workflow and stream it until terminal. Without this or
        /// `--wait`, the command submits and prints the execution id.
        #[arg(long, conflicts_with = "wait")]
        watch: bool,
        /// Submit the workflow and poll until terminal.
        #[arg(long, conflicts_with = "watch")]
        wait: bool,
        /// Initial operator steering/context text to seed before the first wave dispatches.
        #[arg(long, conflicts_with = "context_file")]
        context: Option<String>,
        /// File containing initial steering/context text to seed before first dispatch.
        #[arg(long = "context-file")]
        context_file: Option<PathBuf>,
        /// Declared external-input channel for initial context.
        #[arg(long)]
        channel: Option<String>,
        /// Optional stable input id for the initial context row.
        #[arg(long)]
        input_id: Option<String>,
        /// Source label recorded on the initial external-input row.
        #[arg(long)]
        source: Option<String>,
        /// Optional target stage. Defaults to the channel's declared stage.
        #[arg(long)]
        target_stage: Option<String>,
        /// Optional JSON payload string to carry alongside initial context.
        #[arg(long)]
        payload_json: Option<String>,
        /// Include full execution outputs in `--watch` snapshot lines.
        #[arg(long, requires = "watch")]
        include_outputs: bool,
        /// Maximum seconds for `--wait`.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds for `--wait`.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
    },
    /// Append operator steering/context to a factory workflow run.
    Steer {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Inline steering/context text.
        #[arg(
            long,
            required_unless_present = "context_file",
            conflicts_with = "context_file"
        )]
        context: Option<String>,
        /// File containing steering/context text.
        #[arg(long = "context-file")]
        context_file: Option<PathBuf>,
        /// Declared external-input channel to append into.
        #[arg(long, default_value = "operator_steering")]
        channel: String,
        /// Optional stable input id. Omitted means the server mints one.
        #[arg(long)]
        input_id: Option<String>,
        /// Source label recorded on the external-input row.
        #[arg(long, default_value = "operator")]
        source: String,
        /// Optional target stage. Defaults to the channel's declared stage.
        #[arg(long)]
        target_stage: Option<String>,
        /// Optional JSON payload string to carry alongside text.
        #[arg(long)]
        payload_json: Option<String>,
    },
    /// Show the latest controller decision and whether Kata can apply it.
    Status {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
    },
    /// Show the current live or parked factory candidate packet.
    Candidate {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
    },
    /// Print the unified factory closeout report for one execution.
    Report {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Emit an export-ready report bundle JSON packet.
        #[arg(long)]
        bundle: bool,
        /// Write an export-ready report bundle directory.
        #[arg(long, value_name = "DIR", conflicts_with = "bundle")]
        bundle_dir: Option<PathBuf>,
    },
    /// Apply one controller decision through Kata's policy-aware runtime path.
    Apply {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Exact controller decision id to apply.
        #[arg(long)]
        decision_id: String,
        /// Explicit action to apply or resume. Defaults to the action inferred from the decision.
        #[arg(long)]
        action: Option<String>,
        /// Workflow source to replay for next-wave claim recovery.
        #[arg(long)]
        workflow: Option<String>,
        /// Declared external-input channel for next-wave claim recovery.
        #[arg(long)]
        channel: Option<String>,
        /// Stable external-input id for next-wave claim recovery.
        #[arg(long)]
        input_id: Option<String>,
        /// Source label recorded on the controller-application evidence.
        #[arg(long, default_value = "factory_controller")]
        source: String,
        /// Optional durable candidate label. Used by `park` decisions.
        #[arg(long)]
        name: Option<String>,
        /// Request guarded resume of a previously claimed side effect.
        ///
        /// Supports claims whose recorded side-effect metadata matches the
        /// retry request. Composite `promote_then_advance` resume is only for
        /// claims where promotion has already removed the execution worktree.
        #[arg(long)]
        resume_claimed_side_effect: bool,
    },
    /// Finalize an incomplete controller application claim after verification.
    Finalize {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Exact controller decision id whose application claim is being finalized.
        #[arg(long)]
        decision_id: String,
        /// Explicit action to finalize. Defaults to the action inferred from the decision.
        #[arg(long)]
        action: Option<String>,
        /// Optional known next execution id for advance claims.
        #[arg(long)]
        next_execution_id: Option<String>,
        /// Observed parked ref for park claims.
        #[arg(long)]
        parked_ref: Option<String>,
        /// Observed parked commit sha for park claims.
        #[arg(long)]
        commit_sha: Option<String>,
        /// Observed base ref/bookmark after a promotion side effect.
        #[arg(long)]
        promoted_ref: Option<String>,
        /// Observed commit sha/id now referenced by the promoted base ref/bookmark.
        #[arg(long)]
        promoted_commit_sha: Option<String>,
        /// Source label recorded on the recovery evidence.
        #[arg(long, default_value = "factory_controller_finalize")]
        source: String,
        /// Operator/admin reason for finalizing the claim.
        #[arg(long)]
        reason: String,
        /// Operator/admin proof string. May be repeated.
        #[arg(long = "evidence", required = true)]
        evidence: Vec<String>,
        /// Required acknowledgement that the side effect has already happened.
        #[arg(long)]
        confirm_side_effect: bool,
    },
}

/// Operator subcommands under `kata run`.
///
/// These are intentionally run-scoped controls over an already-running
/// installed Kata main. Starting a workflow is `kata run <workflow>`.
/// Infrastructure starts through `kata serve` or `kata service`.
#[derive(Debug, Subcommand)]
pub enum RunCmd {
    /// List executions known by the API node.
    ///
    /// Server-side paginated + status-filterable: `--limit` bounds the
    /// page and `--status` narrows to one or more lifecycle tags before the
    /// rows cross the wire. The server paginates from the OLDEST end of its
    /// Ulid ordering, so `--limit N` returns the N *oldest* executions (the
    /// terse table then displays that page newest-first). Omit `--limit` for
    /// the full list — all executions, newest-first.
    List {
        /// Maximum number of executions to return, taken from the OLDEST end
        /// of the server's oldest-first page (so `--limit N` is the N oldest,
        /// not the N most recent). Omit for the full list.
        #[arg(long)]
        limit: Option<usize>,
        /// Comma-separated lifecycle-status whitelist
        /// (`pending,running,completed,failed,cancelled`). Omit for all statuses.
        #[arg(long)]
        status: Option<String>,
        /// Emit the full execution records (one JSON object per line)
        /// instead of the terse table — the same stream the global
        /// `--format json` selects.
        #[arg(long)]
        json: bool,
    },
    /// Show one execution record.
    Show {
        /// Execution id (Ulid as a string).
        execution_id: String,
    },
    /// Fetch execution outputs, or one completed stage output.
    Output {
        /// Execution id (Ulid as a string).
        execution_id: String,
        /// Optional stage name. Omit to print the aggregate outputs map.
        stage: Option<String>,
    },
    /// Print the newest execution known by the API node.
    Current {
        /// Restrict to executions that are not terminal.
        #[arg(long)]
        active: bool,
    },
    /// Wait for one execution to reach a terminal status.
    Wait {
        /// Execution id (Ulid as a string).
        execution_id: String,
        /// Maximum time to wait.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
    },
    /// Approve a parked human gate.
    Approve {
        /// Parent execution id.
        execution_id: String,
        /// Assignment id from the approvals list.
        assignment_id: String,
    },
    /// Reject a parked human gate.
    Reject {
        /// Parent execution id.
        execution_id: String,
        /// Assignment id from the approvals list.
        assignment_id: String,
        /// Reason recorded on the rejection.
        reason: String,
    },
    /// Ask every live attempt's worker to stop. Reports how many were ASKED.
    ///
    /// A stop is ACKNOWLEDGED when the worker reports the attempt's terminal, and
    /// until then the execution's workspace stays unreclaimable — `kata run park`
    /// refuses and names the attempt still holding it.
    ///
    /// The stop is recorded durably FIRST, then sent to the worker as a control
    /// frame over its local socket. A worker that
    /// can never answer leaves the recorded stop standing, and `kata run park`
    /// keeps refusing. The exit from that state is
    /// `kata run discharge-stop --attempt-id <id> --lease-epoch <n> --operator
    /// <who> --assertion <what you established>`, reading `attempt_id` and
    /// `lease_epoch` off the `evidence.worker_stops` row that
    /// `kata run show <execution-id>` reports with
    /// `awaiting_worker_acknowledgement: true`.
    Cancel {
        /// Execution id to cancel.
        execution_id: String,
        /// Free-text reason. Defaults to "operator-initiated cancel".
        #[arg(long)]
        reason: Option<String>,
    },
    /// Promote a completed execution's candidate workspace onto the base branch.
    Promote {
        /// Execution id to promote.
        execution_id: String,
    },
    /// Ask a pending forge export's remote and forge again, now.
    ///
    /// A `forge_export` whose push or pull request outcome kata could not read
    /// — the remote or `gh` did not answer — stays pending, and kata asks again
    /// once a minute has passed since the last unanswered read, recording the
    /// effect `workspace_effect_unclassified` at the tenth. Once the remote or
    /// `gh` is fixed (`gh auth login`, the network back), this asks at once
    /// and drives each pending export on: it prints each export's state and its
    /// last intent (verdict, unanswered reads, the last read's error, the
    /// command's error). The ask counts like any other. It waits as long as
    /// the drive takes, with no client read bound: each read of the remote is
    /// bounded at 60 s and each push or `gh` command at 300 s, so a hung
    /// remote can hold it for minutes per pending export. Refused, with
    /// nothing changed, for an execution with no pending export
    /// (`forge_reconcile_nothing_pending`) and for one whose lifecycle is not
    /// `running` — an admitting or finished run.
    ForgeReconcile {
        /// Execution id whose pending forge exports to reconcile.
        execution_id: String,
    },
    /// Park an isolated execution candidate under `refs/heads/parked/...`
    /// without merging it into the base branch.
    Park {
        /// Execution id to park.
        execution_id: String,
        /// Optional parked ref name. Defaults to `parked/<execution_id>`.
        #[arg(long)]
        ref_name: Option<String>,
    },
    /// Discharge an outstanding worker stop that no worker will answer.
    ///
    /// This is the recourse for a stop `kata run show` reports with
    /// `awaiting_worker_acknowledgement: true` under `evidence.worker_stops`.
    /// A stop is normally discharged by the worker's own terminal frame; when
    /// that frame can never arrive — the worker's host is gone, or the worker
    /// died before answering — the stop stands forever, and it refuses the
    /// execution's workspace reclaim (`kata run park`).
    ///
    /// There is NO probe mode: nothing in Kata can prove a worker PROCESS has
    /// exited — heartbeat loss is not proof of it. So `--operator` and `--assertion` are
    /// always required, and the durable record always says a human decided.
    ///
    /// Discharging clears the SAFETY latch. It does NOT re-authorize the work: a
    /// stopped attempt's failure-retry budget stays suppressed, because the stop
    /// is a standing instruction about the attempt. Re-submit the run if you want
    /// the stage to execute again.
    DischargeStop {
        /// Execution id holding the outstanding stop.
        execution_id: String,
        /// The attempt the stop was addressed to — copy it from the `attempt_id`
        /// field of the `evidence.worker_stops` row carrying
        /// `awaiting_worker_acknowledgement: true`.
        #[arg(long)]
        attempt_id: String,
        /// The lease epoch the stop was filed under, from the `lease_epoch`
        /// field of the same row.
        ///
        /// Required, and deliberately not defaulted: a stop is keyed by its
        /// attempt and lease epoch, and the discharge names exactly the row it
        /// clears rather than whichever row a default would pick.
        #[arg(long)]
        lease_epoch: i64,
        /// Who is asserting. An unattributed discharge is indistinguishable from
        /// a machine observation in the durable record. Against a signed-token
        /// main it must be the `issued_for` of your `KATA_API_TOKEN`; any other
        /// name is refused.
        #[arg(long)]
        operator: String,
        /// What you established, recorded verbatim (e.g. "worker host
        /// terminated; PID 4711 is gone").
        #[arg(long)]
        assertion: String,
    },
}

/// Subcommands for `kata node`.
#[derive(Debug, Subcommand)]
pub enum NodeCmd {
    /// The node's `[node] environment`.
    Environment {
        #[command(subcommand)]
        cmd: NodeEnvironmentCmd,
    },
}

/// Subcommands for `kata node environment`.
#[derive(Debug, Subcommand)]
pub enum NodeEnvironmentCmd {
    /// Release a declared Nix environment: its row, its manifest root and its gc roots.
    /// Refused while any non-terminal attempt's capsule binds it
    /// (`environment_bound_to_live_attempt`), and while a main holds the data-directory
    /// lock or the discovery lease (`node_environment_release_requires_stopped_main`):
    /// stop the main first.
    Release {
        /// The environment id, as boot logs it (64 hex digits).
        id: String,
        /// Data directory holding `operational.db`. Takes precedence over `--config`.
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
        /// Config file naming `node.data_dir` when `--data-dir` is omitted.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

/// Subcommands for `kata sandbox` — the by-hash provider store the capsule
/// route resolves its declared provider through.
#[derive(Debug, Subcommand)]
pub enum SandboxCmd {
    /// Provision an EXTERNAL EXECUTION PROVIDER into this node's
    /// by-hash provider store, and print the node configuration that routes to
    /// it.
    ///
    /// A provider is identified by CONTENT, never by `PATH` and never by where
    /// its binary happens to sit. This command copies the directory holding
    /// `kata-provider-<name>` into the store, hashes the COPY, seals it, and
    /// prints the `store:<hex>` address of what it published — which is the only
    /// value `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` accepts.
    ///
    /// It is the ONLY supported way to install a provider, and that is the
    /// point: there is no `PATH` to drop a binary on, so a refusal that
    /// says *"install the provider"* names something an operator can actually
    /// run.
    ///
    /// Idempotent — provisioning byte-identical bytes twice yields the same
    /// address and publishes nothing new.
    InstallExternalProvider {
        /// The provider NAME. The source directory must hold
        /// `kata-provider-<name>`, and this is the value that goes in
        /// `KATA_EXTERNAL_EXECUTION_PROVIDER`.
        #[arg(long)]
        name: String,
        /// The directory holding `kata-provider-<name>`, copied as given: the
        /// `youki` entry an `Egress` capsule runs also needs `kata-oci-hook`
        /// and `ip` in it, and the packaged `share/kata/provider-source` has
        /// no `ip` (its store path is in `share/kata/provider-members.toml`).
        /// A DIRECTORY and not the executable: the entry's name becomes the
        /// content hash of everything in it, so a provider that grows an
        /// adjacent file keeps one address.
        source: PathBuf,
        /// The store root to publish into. Defaults to
        /// `$KATA_EXTERNAL_PROVIDER_STORE`; without either, the command refuses
        /// rather than choosing a location on the operator's behalf.
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

/// Subcommands for `kata login` — kata's OWN login for its embedded agent
/// harness, stored owner-only under the effective owner's home
/// (`~/.config/kata/logins/`). kata never reads another tool's login in its
/// place: not `~/.codex/auth.json`, not `~/.claude/.credentials.json`.
#[derive(Debug, Subcommand)]
pub enum LoginCmd {
    /// Log in to OpenAI: a ChatGPT login (by device code or through the
    /// browser), or an API key.
    ///
    /// Without `--api-key` kata logs in to ChatGPT and stores the login as
    /// `openai-chatgpt.json`; both flows store the same file, and kata
    /// refreshes it itself. Without a flow flag kata picks the flow from the
    /// session: the DEVICE-CODE flow when it is remote (`SSH_CONNECTION` or
    /// `SSH_TTY` is set) or has no graphical display (neither `DISPLAY` nor
    /// `WAYLAND_DISPLAY` is set), otherwise the BROWSER flow. An empty
    /// variable counts as unset.
    ///
    /// The device-code flow prints a URL and a one-time code to enter on any
    /// device, and waits until the code is approved or expires. The browser
    /// flow opens a browser on the ChatGPT authorization URL (and prints it),
    /// and waits up to five minutes for the callback on localhost:1455 (or
    /// 1457); on a remote host, forward the port first: `ssh -L
    /// 1455:localhost:1455 <host>`. Ctrl-C stores nothing.
    Openai {
        /// Store an API key read from stdin (never from the command line) as
        /// `openai-api-key`, instead of the ChatGPT login.
        #[arg(long)]
        api_key: bool,
        /// Use the device-code flow, whatever the session.
        #[arg(long, conflicts_with_all = ["api_key", "browser", "no_browser"])]
        device_code: bool,
        /// Use the browser flow and open a browser, whatever the session.
        #[arg(long, conflicts_with_all = ["api_key", "no_browser"])]
        browser: bool,
        /// Use the browser flow without opening a browser: print the
        /// authorization URL only.
        #[arg(long, conflicts_with = "api_key")]
        no_browser: bool,
    },
    /// Store an Anthropic API key read from stdin as `anthropic-api-key`.
    ///
    /// `--api-key` is required: kata holds no Claude subscription login in
    /// this build.
    Anthropic {
        /// Store an API key read from stdin (never from the command line).
        #[arg(long, required = true)]
        api_key: bool,
    },
    /// Report every kata login, offline: present, owner-only, its kind, the
    /// access token's expiry and whether a refresh token is stored. Without
    /// `--check` it contacts no issuer and refreshes nothing.
    Status {
        /// Also check each stored login with ONE authenticated read that
        /// spends nothing: an API key against its provider's model list, the
        /// ChatGPT login against the ChatGPT backend's usage read (refreshed
        /// first, as a turn would, when its access token is about to expire).
        /// Each is reported `ok`, `refused`, `expired` or `unchecked` (no
        /// answer judged it), and any stored login that is not `ok` fails the
        /// command.
        #[arg(long)]
        check: bool,
    },
}

/// A provider kata holds a login for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LoginProviderArg {
    /// OpenAI (`openai-chatgpt.json`, `openai-api-key`).
    Openai,
    /// Anthropic (`anthropic-api-key`).
    Anthropic,
}

/// Subcommands for `kata host` — preparing a host for the rootless-youki
/// `oci` execution profile.
///
/// These verbs own the shipped containment plane's host policy: the pinned
/// youki's exact-path AppArmor profile first.
#[derive(Debug, Subcommand)]
pub enum HostCmd {
    /// Write the pinned youki's exact-path AppArmor profile to
    /// `/etc/apparmor.d/<profile_name>` and reload it with
    /// `apparmor_parser -r`.
    ///
    /// ROOT ONLY, and it never escalates itself: a profile is host policy, so
    /// the privilege comes from the operator — `sudo kata host
    /// apparmor-install`. It verifies the pinned bytes before
    /// writing — through the same producer `certify_youki` runs — and writes
    /// nothing when any check refuses. The grant is exact-path, never a glob,
    /// and never a `kernel.apparmor_restrict_unprivileged_userns` relaxation:
    /// an upgrade changes the Nix store path, the profile stops attaching,
    /// and the certification refuses until an operator re-pins and
    /// re-installs — that refusal is the mechanism.
    ApparmorInstall,
    /// Prepare this host and this project for the `oci` execution profile,
    /// end to end.
    ///
    /// Runs the host checks by name (Linux x86-64, Nix, cgroup v2,
    /// unprivileged user namespaces), realises and verifies the pinned youki,
    /// reports the AppArmor profile state — and with `--install-apparmor`
    /// runs `sudo kata host apparmor-install` itself, the privilege still
    /// supplied by the operator through sudo — provisions the shipped
    /// `kata-provider-youki` into a by-hash provider store, writes the
    /// provider exports and the `[node]` oci declarations into the project
    /// `.env` and `--config`, refusing rather than overwriting a conflicting
    /// value the operator declared (the exports it wrote to `.env` itself
    /// are its own, and a re-run updates them), and finishes by running
    /// `kata doctor`: the run fails unless every required row passes. A
    /// second run changes nothing and says so.
    ///
    /// Run from a checkout build (`target/release/kata`, or a link to it on
    /// `PATH`) with no packaged `share/kata` beside it, it provisions the
    /// provider members built beside the binary and the static
    /// `kata-toolhost` from `x86_64-unknown-linux-musl/<profile>/` in the
    /// binary's own Cargo target directory (the checkout's `target/` for
    /// `target/release/kata`), and builds the pinned youki
    /// (when absent) and the `ip` and default environment declarations from
    /// the checkout's `nix/youki.nix` and `nix/share.nix` with `nix-build`,
    /// rooting each under `.kata/nix-roots`; the build's log streams to the
    /// terminal. After a rebuild, re-run it to provision the new provider
    /// members.
    Setup {
        /// The project config to write, created by the same scaffold `kata
        /// init` runs when absent.
        #[arg(long, default_value = ".kata/kata.toml")]
        config: std::path::PathBuf,
        /// Run `sudo kata host apparmor-install` when the pinned youki's
        /// AppArmor profile is not installed and loaded — invoke `kata host
        /// setup` from a terminal, because sudo's password prompt needs a
        /// tty. Without it the command is printed for the operator to run
        /// instead, and the run reports `incomplete` until the profile lands.
        #[arg(long)]
        install_apparmor: bool,
        /// The `[node] environment` declaration to merge into `--config`,
        /// in the `node-environment.toml` shape `just node-environment`
        /// prints. Defaults to the packaged `share/kata/node-environment.toml`
        /// beside this binary, or, for a checkout build, the one
        /// `nix/share.nix` builds.
        #[arg(long)]
        environment_file: Option<std::path::PathBuf>,
        /// The directory holding the provider's kata-built members
        /// (`kata-provider-youki`, `kata-oci-hook`, `toolhost/kata-toolhost`).
        /// Defaults to the packaged `share/kata/provider-source` beside this
        /// binary, or, for a checkout build, the members built beside it and
        /// the musl `kata-toolhost` of the same profile.
        #[arg(long)]
        provider_source: Option<std::path::PathBuf>,
        /// The iproute2 `ip` the provider entry receives — it must resolve to
        /// a regular executable file under `/nix/store`, which is copied
        /// verbatim. Defaults to the store path the packaged
        /// `share/kata/provider-members.toml` beside this binary declares, or,
        /// for a checkout build, the one `nix/share.nix` builds.
        #[arg(long)]
        provider_ip: Option<std::path::PathBuf>,
    },
}

/// Subcommands for `kata execution-provider`.
///
/// The trust model is only a trust model if an operator can inspect it. Each of
/// these reads `kata_worker::sandbox_posture::observe()` and
/// `ExecBackend::provider_posture()`, and `certify` also runs the one rootless-OCI
/// certification (`certified_oci_route`); none re-derives a containment fact.
#[derive(Debug, Subcommand)]
pub enum ExecutionProviderCmd {
    /// List every containment provider this BUILD knows and what it ships for
    /// each: certified containment, explicitly unconfined, or no runtime at all.
    ///
    /// A build-axis question — the answer is identical on every host. Use
    /// `inspect` for what THIS host can actually deliver.
    List,
    /// Show the full containment posture for one provider: the pinned rootless-OCI
    /// runtime's bytes, its userns/AppArmor prerequisites, its seccomp witness,
    /// this process's cgroup delegation, every containment lever, and the
    /// build's known containment limits. Starts no container.
    Inspect {
        /// Backend spelling, `oci` or `host`.
        #[arg(default_value = "oci")]
        provider: String,
    },
    /// Answer, with an exit code, whether this host can deliver a provider's
    /// declared containment.
    ///
    /// Emits the same report as `inspect` plus the one rootless-OCI certification
    /// (functional probe included) and its verdict; exits non-zero on refusal so
    /// a script can branch on it. `certify` and `kata doctor` ask DIFFERENT
    /// questions and may honestly disagree: a host without the pinned runtime
    /// fails `certify oci` while doctor only warns.
    Certify {
        /// Backend spelling, `oci` or `host`.
        #[arg(default_value = "oci")]
        provider: String,
    },
}

/// Native per-user lifecycle for the one installed durable main.
#[derive(Debug, Subcommand)]
pub enum ServiceCmd {
    /// Preview or install the systemd-user unit / launchd LaunchAgent.
    ///
    /// The service runs under an owner-only environment snapshot taken by
    /// this install, not your shell's environment, and never reads `.env`. It
    /// copies the provider declaration `kata host setup` writes (the three
    /// `KATA_EXTERNAL_*` keys) and the variable of every `[agents.<label>]`
    /// declaring `mode = "api_key", source = "env:<VAR>"`, and refuses while
    /// one is unset — only when the config has a `supervised_node` transport,
    /// whose node inherits the service's environment; otherwise the main
    /// starts no node. Re-run with `--apply` (service
    /// stopped) after re-running `kata host setup` or to rotate a key.
    Install {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Preview or start the installed service definition.
    Start {
        #[arg(long)]
        apply: bool,
    },
    /// Preview or stop the installed service definition.
    Stop {
        #[arg(long)]
        apply: bool,
    },
    /// Preview or restart the installed service definition.
    Restart {
        #[arg(long)]
        apply: bool,
    },
    /// Show the native service-manager status.
    Status,
    /// Show recent native service-manager logs.
    Logs,
    /// Preview or uninstall the user service definition without deleting data.
    Uninstall {
        #[arg(long)]
        apply: bool,
    },
}

/// Subcommands for `kata workflows`.
#[derive(Debug, Subcommand)]
pub enum WorkflowsCmd {
    /// List all workflows available in the standard library.
    ///
    /// By default shows only the *effective* entries — one per name,
    /// with the highest-priority root winning. `--all` shows every
    /// match including shadowed rows so operators can see exactly
    /// which file a name will resolve to.
    List {
        /// Show every matching file, including shadowed rows.
        #[arg(long)]
        all: bool,
    },
    /// Print the resolved file path, source format, and a short
    /// summary (stage count + edges) for a named workflow.
    Inspect {
        /// The workflow name (file stem, without `.star`).
        name: String,
        /// Node config (`kata.toml`) whose `[node]` facts this judgment
        /// installs — the same door `kata check --config` carries.
        #[arg(long, env = "KATA_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Compile and preflight a workflow without executing it.
    Check {
        /// Workflow library name or path to a `.star` file.
        workflow: Option<String>,
        /// Check every effective workflow in the layered library.
        #[arg(long)]
        all: bool,
        /// Exit nonzero when the checked execution program has warnings.
        #[arg(long)]
        deny_warnings: bool,
        /// Node config (`kata.toml`) whose `[node]` facts this judgment
        /// installs — the same door `kata check --config` carries.
        #[arg(long, env = "KATA_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Drive a workflow with RECORDED stage outputs and assert its routing
    /// (branch / loop / skip) + rendered prompts — deterministically, with no
    /// live models. The fixture is a JSON document; see
    /// `test/fixtures/workflows/README.md` for the format.
    Test {
        /// Path to a fixture JSON file.
        fixture: String,
        /// Print the rendered prompt for every stage the fixture drove.
        #[arg(long)]
        show_rendered: bool,
    },
    /// Print the machine-readable catalog of the native Starlark DSL surface:
    /// every builtin's signature (kwargs, types, required/optional, defaults)
    /// plus the contract grammar and decision-tag/verdict vocabulary. An agent
    /// author can target this schema instead of reverse-engineering the DSL
    /// from examples.
    ///
    /// The global `--format json` emits the same catalog bare: it is no
    /// operation's response, so it carries no envelope.
    Schema,
}

/// Subcommands for `kata skill` — wire kata into a host coding agent.
#[derive(Debug, Subcommand)]
pub enum SkillCmd {
    /// Register kata as an MCP server for a host agent AND install a kata skill
    /// teaching that agent the author → check → run → observe loop through the
    /// kata MCP tools.
    ///
    /// For `--host claude-code` this writes two project-local files, both
    /// idempotently (re-running updates in place, never clobbering unrelated
    /// content):
    ///
    /// * `.mcp.json` — an ADDITIVE merge of a `mcpServers.kata` entry that
    ///   launches `kata mcp` (any other servers already present are preserved).
    /// * `.claude/skills/kata/SKILL.md` — the kata authoring-loop skill.
    Install {
        /// Host coding agent to wire kata into.
        #[arg(long, value_enum)]
        host: SkillHost,
        /// Project directory to install into. Defaults to the current
        /// directory. The MCP registration + skill file are written relative
        /// to this root.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

/// Host coding agent selector for `kata skill install`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum SkillHost {
    /// Anthropic Claude Code — reads `.mcp.json` (`mcpServers`) and
    /// `.claude/skills/<name>/SKILL.md`. Fully automated.
    ClaudeCode,
    /// OpenAI Codex CLI. No project-local MCP registration or skill file
    /// format exists (Codex reads a GLOBAL `~/.codex/config.toml`), so
    /// `install` prints the manual registration steps rather than mutating a
    /// user-global file. See the command output for the narrowing.
    Codex,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Validate a config file by parsing it as TOML and printing a summary.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
}

/// Scope selector for `kata api-token mint`, mapping to
/// [`kata_types::identity::ApiScope`]. The three tiers form the monotone ladder
/// `admin ⊇ approve ⊇ operate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum CliApiScope {
    /// Reads + workload-driving mutations (submit/run, steer, watch). The
    /// agent / MCP surface's scope; cannot resolve human gates.
    Operate,
    /// Human-gate mutations (approve/reject/cancel/answer/promote/park).
    Approve,
    /// Destructive / administrative routes; also the fail-closed default.
    Admin,
}

impl From<CliApiScope> for kata_types::identity::ApiScope {
    fn from(s: CliApiScope) -> Self {
        match s {
            CliApiScope::Operate => Self::Operate,
            CliApiScope::Approve => Self::Approve,
            CliApiScope::Admin => Self::Admin,
        }
    }
}

/// Subcommands for `kata api-token`.
#[derive(Debug, Subcommand)]
pub enum ApiTokenCmd {
    /// Mint a scoped, ed25519-signed API bearer token and print its
    /// base64url wire form to stdout, ready for `Authorization: Bearer <token>`.
    ///
    /// Requires the main's PRIVATE ed25519 signing key — the same key
    /// whose PUBLIC half the API verifies against
    /// (`[api.auth].verifying_key_env` / `verifying_key_file`). Supply it as a
    /// file (`--signing-key-file`, credential material — `chmod 600`) or via
    /// the `KATA_API_SIGNING_KEY` environment variable. Signing material is an
    /// operator CLI input, not daemon configuration. The scope is bound into the signature, so
    /// a holder can neither forge a token nor escalate its own scope.
    Mint {
        /// Authorization scope the token grants.
        #[arg(long, value_enum)]
        scope: CliApiScope,
        /// File holding the hex-encoded ed25519 private signing key (a 32-byte
        /// seed, 64 hex chars; `chmod 600`). When omitted, the key is read from
        /// the `KATA_API_SIGNING_KEY` environment variable.
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// Label naming who/what the token is issued for, bound into the
        /// signature. A signed-token main records it as the approver of a gate the
        /// token approves, and a stop discharge under the token must name it as its
        /// `--operator`. Refused when blank or padded with whitespace.
        #[arg(long, default_value = "operator-cli")]
        issued_for: String,
        /// Optional validity window from now: `<n>` followed by a unit
        /// `d`(ays) / `h`(ours) / `m`(inutes) / `s`(econds), e.g. `30d`. Omit
        /// for a non-expiring token.
        #[arg(long)]
        expires_in: Option<String>,
    },
}
