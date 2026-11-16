# Operator guide

Build with `just build`, validate configuration with `just config-check`, and start
the single authoritative service with
`systemd-run --user --scope -p Delegate=yes -- kata serve --config <path>` — both
`kata serve` and `kata host setup` refuse from an undelegated login shell. Clients
attach to that service; workers are subordinate execution capacity and do not own workflow
state. Author workflows only in Starlark. Shipped inputs live in `workflows/std`,
`workflows/examples`, and `workflows/kata-factory`. The gate's smoke rigs live in
`workflows/smoke`: no install carries them and a checkout build does not resolve them;
an explicit `KATA_STDLIB_DIR` naming a checkout's `workflows/std` adds its `smoke`
sibling as the lowest-priority root, which is how the tests, the smoke recipes and
`just workflows-check-all` reach them.

Configuration is closed. `kata.toml` and a `kata-worker` daemon's own file refuse a key
they do not declare, naming where it sits (`failed to parse kata.toml at
`runtime.max_concurrent_dispatch`: … unknown field …`) — at `kata config check`, at
`kata serve`, on a reload (which keeps the previous config and logs the refusal), and in
`kata restore --restore-config`, which validates the bundled config before restoring it.
That holds in every section and every table nested in one, `[node] environment`'s
`integrity_policy` and each worker `capabilities` entry (beside `kind` and inside `data`)
included. Two places take names you choose rather than keys kata declares: the labels
under `[agents]` and the variable names in an agent's `env`. Two refusals in an agent
block name their own cause instead, at load, naming the block: a `type` key under any
label (`agent_type_removed` — the label says what a block is, and the harness is always
kata's embedded one, its provider the `adapter`; delete the line), and any key under a
reserved label, `[agents.shell]` or `[agents.workspace_effect]`
(`shell_agent_block_keys`, naming each key — the shell route takes none). There is no
`[workflows]` table — workflows are Starlark packs discovered from the library roots.

Use `kata init` and `kata doctor` for first-run setup, `kata run` for execution, and
`kata status`, `kata watch`, and `kata evidence` for observation. Preview durable
schema changes with `kata upgrade --dry-run`; "Durable formats and upgrades" below says what
this binary refuses and the recourse for each.

A `subworkflow(pack = ..)` child is resolved through the checking process's workflow
library roots (`kata workflows list` prints them) and embedded in the parent's checked
program, so `kata workflows check` of a parent needs the child pack in one of those
roots. Editing the child pack after the parent is admitted does not change what that
parent runs. A cyclic chain of subworkflows, or one more than 8 levels deep, is refused
at check. Linux containment refuses when its
required kernel capability is unavailable; it does not silently weaken isolation.

The primary install is a source build: `cargo build --release --locked` in a
checkout builds the workspace's `default-members` — exactly `kata`,
`kata-worker`, `kata-provider-youki` and `kata-oci-hook` — and `cargo build
--release --locked --target x86_64-unknown-linux-musl -p kata-toolhost` builds
the static `kata-toolhost`, a nanocode agent capsule's init, into
`target/x86_64-unknown-linux-musl/release/`. `just install` runs both builds
and links `kata` and `kata-worker` into `~/.local/bin`
(`KATA_BINDIR` overrides it). The links are what make it a checkout build:
kata resolves its own path to `<checkout>/target/release/`, where it finds the
workflow library (`workflows/`), the provider members and the checkout's Nix
expressions; a copied binary, or one built into a `CARGO_TARGET_DIR` outside
the checkout, is not a checkout build (`just install` unsets the variable for
its build). The provider members `kata host setup` provisions are copies, so a
rebuild that changes them takes a re-run of `kata host setup` (below). The
alternative is the flake's package: `just install-nix` runs `nix profile
install .#kata` for the invoking user, and the `katacode` Cachix cache
(declared in `flake.nix`'s `nixConfig`) substitutes the build when it has been
pushed. `just package` writes the relocatable tree under `target/dist/` — that
package copied out of the store. Eval tasks live under `test/eval/tasks`;
`just eval` is deterministic and `just eval-live` may spend provider budget.

## Rootless OCI prerequisite (Linux x86-64)

Rootless OCI execution runs through ONE pinned youki: `config/youki-pin.toml` names
the command that realises it, its version, exact Nix store path and sha256, and every
surface reads that file (`kata doctor` carries the pin embedded at build time; rebuild
after re-pinning). A host with `kernel.apparmor_restrict_unprivileged_userns=1` places
an *unprofiled* binary into the kernel's `unprivileged_userns` profile, which denies
`capability`, so the user-namespace unshare fails with EPERM — youki and `runc`
identically. The remedy is one AppArmor profile naming the pinned executable's exact
path: never a glob, and never relaxing the sysctl.

```console
$ kata doctor                       # the containment_* rows: pin, profile, seccomp and delegation state, no root needed
$ sudo kata host apparmor-install   # verify the pinned bytes, write the profile, reload it
```

`kata doctor`'s `containment_runtime`, `containment_userns`, `containment_syscall_fence`
and `containment_cgroup_delegation` rows read the same state without root, through the
certification's own folds; `kata execution-provider certify oci` and `just
feasibility-probes` are the surfaces that observe a container actually starting. An upgrade produces a different store path, so the profile stops
attaching and the probe refuses: re-pin `config/youki-pin.toml`, rebuild `kata`, re-run
`sudo kata host apparmor-install`, and re-run the probe.

### What `kata doctor` and `just host-check` report

`kata doctor`'s containment rows are the rootless-OCI route's prerequisites and nothing
else — there is no other engine to report on:

| Row | Passes when | Otherwise |
|---|---|---|
| `containment_runtime` | the pinned youki holds exactly the pinned bytes | `fail` on a digest mismatch (the pin is stale or the store damaged); `warn` with the realise command when the binary is absent |
| `containment_userns` | the pinned youki's exact-path AppArmor profile is installed byte-identical to the render — required on EVERY kernel, because the row reads the certification's own AppArmor fold — and it is loaded, or the kernel does not restrict unprivileged user namespaces | `warn` (degraded) when the profile is installed, the kernel restricts user namespaces, and its loaded-profile list needs `CAP_MAC_ADMIN` to read — `kata execution-provider certify oci` starts a container and settles it; `warn` naming `sudo kata host apparmor-install` when the profile is missing, differs, or is not loaded, on an unrestricted kernel too (the certification refuses that host) |
| `containment_syscall_fence` | the pinned youki reports a `libseccomp:` line, the witness that it loads `linux.seccomp` | `warn`; not measured when the runtime's bytes did not verify |
| `containment_cgroup_delegation` | THIS process's cgroup v2 delegation carries memory and pids | `warn`: measured for the shell running doctor — a worker under a delegated scope (`systemd-run --user --scope -p Delegate=yes`, or a `kata service install` unit) measures its own |
| `containment_env_levers` | the three `KATA_EXTERNAL_*` provider declarations in THIS environment resolve through the capsule route admission's own resolver: a provider name, its content address, and a store root whose entry hashes to that address | `warn` carrying admission's refusal — no provider declared (`oci_provider_undeclared`), half a declaration, a malformed one, or a store entry that does not resolve; either way the row lists every lever SET or unset, the count of the build's known containment limits, and `kata execution-provider inspect oci` for the detail |

Doctor exits non-zero only on a `fail`: a declared requirement this node cannot honour (an
unparseable pin, or a digest mismatch). A host without the pinned runtime, without the
AppArmor profile, or measured from an undelegated shell is a legitimate install that
cannot run capsules yet, so it warns. `kata execution-provider certify oci` asks the
stricter question — it runs the one rootless-OCI certification, functional probe included,
and exits non-zero on refusal — so the two may honestly disagree.

`just host-check` answers "can this host finish the gate" in seconds. Its containment half
(`_containment-preconditions`, which `gate-containment` also runs first) prints one row per
functional probe: `pidfd`, `userns`, `seccomp`, `code mode filter` (a filter with
`SECCOMP_FILTER_FLAG_TSYNC` installs and its `kill_process` action ends a child by
`SIGSYS`: what every Code Mode interpreter does to itself; the tree half asks it too,
since the commit tier's Code Mode suites need it), `cgroup v2` (memory, pids, cpu),
`delegated cgroup`, `flock`, `attachment` (no stale installed-main descriptor), the
BLOCKING `rootless OCI` row (the pinned youki actually starting a rootless `/bin/true`
container), and `loadavg` (reported, never blocking). On a host with
`kernel.apparmor_restrict_unprivileged_userns = 1` (Ubuntu's default) an unprofiled
`unshare` is refused while the profiled youki still creates its namespace, so the `userns`
row reads `restricted — AppArmor admits only profiled binaries; the rootless OCI row proves
youki's` and does not block; the `rootless OCI` row below it is the proof.

### The pinned runtime is built FROM THIS REPOSITORY, and must report libseccomp

The pin is realised from the kata checkout by
`nix build -o .kata/youki-root -f nix/youki.nix`, not by
`nix profile install nixpkgs#youki`, and the difference is the syscall fence. The
`-o` is not cosmetic: that symlink is an indirect GC root, and without one the
pinned bytes are collected by the next `nix store gc` — a pin naming a collected
path refuses as `binary_absent` for a runtime nobody uninstalled. `.kata/` is
gitignored; `readlink .kata/youki-root` prints the store path to re-pin, and
`nix profile install -f nix/youki.nix` roots it in a profile instead.
The nixpkgs derivation builds the `youki` binary crate with
`--features systemd` only; that crate declares no default features and takes
`libcontainer` with `default-features = false`, so `libcontainer/libseccomp` is off.
The resulting runtime does not error on a bundle's `linux.seccomp` section — it
DROPS it, logging a warning nothing reads. A container started from a bundle carrying
every one of kata's deny entries reported `Seccomp_filters: 0`. `nix/youki.nix` is the
same upstream release (0.7.0, the newest) with that feature added, plus two patches:
`nix/youki-0.7.0-foreground-prereap.patch`, a backport that closes 0.7.0's lost-`SIGCHLD`
race — without it `youki run` can wait forever on a container that already exited — and
`nix/youki-0.7.0-atomic-state-save.patch`, which saves `state.json` by temporary file and
rename, so `youki kill`, `state`, `list` and `delete` never read a truncated document
while another youki process is saving it (`scripts/youki-state-tear-probe.sh` measures it).
The derivation's check phase runs youki's own test suite one test at a time: in parallel,
0.7.0's forking tests can fork while another test holds the process's environment lock,
and the forked child then waits on that lock forever, so a `kata host setup` that
builds youki never finishes.

So `certify_youki` refuses `seccomp_unsupported` unless the pinned binary's own
`youki --version` carries a `libseccomp:` line, and `just feasibility-probes`' youki
row refuses the same binaries. That line — not `youki features`, whose
`linux.seccomp` field youki 0.7.0 never populates and which reports `null` on both
builds — is the witness, because youki prints it under the very `#[cfg]` that gates
every seccomp call in the runtime's init.

A youki installed any other way will therefore be refused by name even when it
starts containers perfectly. That is the mechanism, not a defect: a fence the
runtime silently ignores is worse than no fence, because every surface reports it
present.

## Preparing a host and project for `oci`: `kata host setup`

`kata host setup` runs the whole preparation above as one named, idempotent
sequence — it is the supported path from a checkout build or `nix profile
install .#kata` to a running `oci` node, not a shortcut around it:

```console
$ systemd-run --user --scope -p Delegate=yes -- kata host setup
      # probe, provision, declare, then run kata doctor
$ systemd-run --user --scope -p Delegate=yes -- kata host setup --install-apparmor
      # the same, and run `sudo kata host apparmor-install` for you —
      # the privilege still supplied by sudo
```

By named step it: reports the platform (Linux x86-64 only), Nix (`nix-store
--version`, then `nix store info` — the call the main makes at boot, which needs the
`nix-command` feature and a running daemon; without them the step refuses with
`nix_command_unavailable`), cgroup v2 delegation, and unprivileged user
namespaces; realises the pinned youki and verifies its digest against
`config/youki-pin.toml`, GC-rooting the store path under the project's
`.kata/nix-roots`; reports the AppArmor profile state
through the certification's own fold — without `--install-apparmor` a missing,
differing or unloaded profile prints the exact `sudo kata host apparmor-install`
action rather than relaxing anything, and a profile installed byte-identical to
the render whose load an unprivileged caller cannot read (the kernel's
loaded-profile list needs root) takes the certification's functional arm,
starting one rootless `/bin/true` container of the pinned youki: in place when
it starts; deferred to the install action when it does not and the runtime's
refusal reads as an AppArmor denial (its stderr names AppArmor, or carries the
EPERM an unprofiled runtime takes on a restricted kernel); and refused by the
certification's own token (`functional_harness`, `functional_run_refused`), with
no install offered or run, when the start failed for any other reason — no
profile install changes that. What the start
shows depends on the kernel: under `apparmor_restrict_unprivileged_userns` it
shows a profile admitting the runtime is in force; on a kernel that does not
restrict unprivileged user namespaces the container starts with no profile
loaded, so the step says the load is not observed — the same pair (an unknown
load, a container that ran) `certify_youki` admits. With `--install-apparmor`
the step re-takes that arm after the privileged install and refuses when the
container still does not start, rather than reporting the reload's exit status
as the load — as a failed install when the refusal still reads as AppArmor's,
and by the certification's own token, as above, when it does not;
provisions the shipped `kata-provider-youki`, `kata-oci-hook` and
`toolhost/kata-toolhost` (the static init of a nanocode agent capsule, bound
read-only at `/.kata`) from `share/kata/provider-source` (or `--provider-source
<dir>`; a source missing any of the three is `provider_source_incomplete`,
naming it), together with the
iproute2 `ip` the hook runs, into a by-hash provider store under
`.kata/providers` — `ip` is not part of the kata package: it is copied verbatim
from the Nix store path `share/kata/provider-members.toml` declares (or
`--provider-ip <path>`), which must resolve to a regular executable file under
`/nix/store`. A checkout build — the running executable resolves under a kata
checkout's `target/`, with no packaged `share/kata` beside it — reads no
packaged tree: it stages the two members built beside it and the static
toolhost from `x86_64-unknown-linux-musl/<profile>/` in the running binary's
own Cargo target directory (`target/x86_64-unknown-linux-musl/release/` for
`target/release/kata`), the profile being the running binary's (a member missing there is
`provider_source_incomplete`, naming the path probed, and for the toolhost the
build that makes it), takes `ip` and
the default `[node.environment]` from one `nix-build --out-link
.kata/nix-roots/kata-share nix/share.nix` of the checkout (the expression the
flake package installs both files from), and builds an absent pinned youki
with `nix-build --out-link .kata/nix-roots/<store object> nix/youki.nix`.
`nix-build`'s log streams to the terminal while it runs; a failing build is
`checkout_build_failed`, carrying the argv and the exit status. No declaration
is `provider_ip_absent`, a declaration file that does not parse is
`provider_ip_declaration`, a declared path that is not such a file is
`provider_ip_unusable`, and a source directory that holds an `ip` of its own is
`provider_source_holds_ip`; writes the three `KATA_EXTERNAL_*` provider exports
into the project `.env`, under a comment block of its own; merges the
`[node.environment]` declaration (from `share/kata/node-environment.toml` or a
checkout build's `nix/share.nix`, or `--environment-file`) and `egress_allow = []`
into `--config` — a pre-existing `[node]` key the section does not
declare refuses the merge, naming the key, rather than being written back —
and finishes with `kata doctor` — the run reports `status: complete` only when
every required row passes AND no action was left for the operator.

Every step is idempotent: a second run reports `changed no` and writes nothing.
A rebuild of a checkout build changes the provider members' bytes and so their
address: the re-run provisions the new entry beside the old one and replaces
the stale values in its own `.env` block. A different value the operator
declared elsewhere in `.env` refuses `env_file_conflict`, and one in the
environment kata was launched with (not a value `.env` supplied) refuses
`provider_env_conflict`; neither is overwritten.
A refusal names its step and its recourse — a host fact kata cannot verify is
reported, never assumed. The AppArmor step is the one that can remain deferred
on a run without root: the run reports `status: incomplete`, exits non-zero,
and lists `actions required:` naming the exact sudo command — a deferred run
is not a green one, because on a restricted host every capsule would EPERM
until the profile lands. A later `sudo kata host apparmor-install` plus a
re-run of `kata host setup` closes it, and that re-run needs no root: it reads
the installed file and takes the certification's functional arm (the pinned
youki's container starting), so it reinstalls nothing and still reports
`changed no`. One more
layout rule: `.env` is written
only for the `.kata/kata.toml` `--config` shape — the project-root location
dotenvy loads. Any other `--config` shape cannot host a readable `.env`, so
the run defers the three exports as `export KEY=value` actions instead of
writing a file nothing reads.

**The provider declaration under `kata service install`.** An installed main
never reads `.env`: it runs under the owner-only environment snapshot the
install takes. So `kata service install` copies the three `KATA_EXTERNAL_*`
keys `kata host setup` declares from the environment it runs in (as an
ordinary CLI process it loads the project `.env`, so run it from the project
directory, or with the keys exported) into that snapshot; the values never
enter the unit file. A main with a `supervised_node` transport starts its node
under that snapshot (the node never loads a `.env` of its own: it inherits the
main's environment), and the node admits its capsule route before it enrolls, so the
install refuses, naming each missing key, when the declaration is absent — run `kata
host setup` first. A main with no `supervised_node` transport starts no node, so its
install does not require them.
The snapshot holds the values at install time: after re-running `kata host
setup` (a new provider address, a moved store), stop the service, re-run
`kata service install --config <path> --apply`, then start it.

## Execution profiles: `oci` is the only engine

There is one execution engine, and nothing selects it: no config key names an engine,
and like every key a section does not declare, one that tries is refused at load,
naming the key — in `kata.toml` and in a `kata-worker` daemon's own file. A worker
handshake whose Hello carries a key outside the main's declared Hello vocabulary is
rejected at the handshake: the main logs the key and closes the connection. The engine runs
each SHELL stage as a capsule in a rootless OCI container planned by kata, on the pinned
youki above — and each declared agent stage the same way, as a `CapsuleProcess::Agent`
turn driven by a worker-owned adapter — and runs the `parallel()` join, `branch()`,
`sleep()`, `subworkflow()`, `loop()` and `memory_snapshot()` in the
main itself, with no container (see "What runs in the main under `oci`" below). Under `oci`,
`kata workflows check` refuses, by name:

- an agent stage whose `[agents.<label>]` block, adapter, credential or credential
  source the node does not declare or cannot serve (`adapter_undeclared`,
  `adapter_unqualified` for an adapter label that names no kind — every label but
  `nanocode_openai` and `nanocode_anthropic`, the vendor adapters kata no longer
  ships (`codex_app_server`, `generic_acp`, `grok_acp`, `pi_rpc`) included, the
  refusal naming the nanocode kinds — and `credential_undeclared` for a credential
  the block does not declare or the build cannot parse, a source other than
  `kata_login` or `env:<VAR>` such as a host login's `codex_login` included), for the
  primary and every fallback panel member;
  a block has no `argv` or `egress_extra` to declare — the kind fixes the launch
  and its capsule opens no endpoint of its own, so the config load refuses either
  as an unknown field — and declares a `credential`, the only thing that serves
  its model calls (`credential_undeclared` naming its `kata login`), and
  `nanocode_anthropic` declares no `mode = "subscription"`
  (`credential_mode_unsupported`); or whose declared `env` names a variable kata
  itself renders (`capsule_agent_env_*`); every one of these refusals that a
  declared block alone decides — all but a label with no block, which only a pack's
  stage can name — is also refused by `kata config check`, for every harness
  `[agents.<label>]` block, whether or not a pack selects it, under the same names,
  every such block named at once after a summary that says the config parsed and
  validated (it loads, and boot installs the block; the selecting stages are what
  is refused)
  (the shell route under a reserved label — `[agents.shell]` or
  `[agents.workspace_effect]`, an empty block — declares no capsule, so `kata config
  check` skips it, and its summary reports a node whose every block is one as having
  no model agent); `kata doctor`'s `agent_backends` row asks the same one judgement
  of every harness block and fails a refused one, its line carrying the refusal,
  door name first (`kata restore --recoverable` asks the same row of its target
  config, under that config's `[node]`);
- a stage authoring `sandbox = "host"`, or naming a sandbox profile the pack does
  not declare (`host_sandbox_unsupported_under_oci`) — a capsule cannot carry the
  host;
- a knob the capsule route cannot honour, each by name rather than dropped:
  `secrets` on ANY stage class's profile (`profile_secrets_unsupported_under_oci` — a
  capsule carries no pack-declared secret channel for a shell command or an agent
  turn; an agent's credential is the node's `[agents.<label>]`),
  `allowed_tools` (`allowed_tools_unsupported_under_oci`), `required_capabilities`
  (`required_capabilities_unsupported_under_oci`), a per-stage `toolchain` or
  `rootfs` pin (`per_stage_toolchain_unsupported_under_oci` — a capsule's tools are the
  node environment's; say what the stage needs with `requires`), and
  `image.ref`/`image.cpus` (`per_stage_image_unsupported_under_oci` — a capsule
  launches no per-stage image and enforces no cpu quota; `image.memory_mb` alone
  stays honoured);
- a profile whose `requires = [..]` names a program the node's bound `[node]
  environment` does not provide on its `PATH` (`environment_requirement_unmet`; judged
  when the checking process has bound the environment — a booted node — and otherwise at
  dispatch, `capsule_requirement_not_in_environment`);
- any shell stage whose sandbox profile materializes no workspace — a capsule maps
  the execution's durable head under `workspace = "ro"` / `"rw"`, or the canonical
  empty tree under `workspace = "scratch"`, whose delta is recorded as evidence and
  never applied;
- a `net = "host"` stage, shell or agent, on a node whose `[node] egress_allow`
  declares no authorities (`egress_undeclared`; `net = "offline"` is the spelling
  for no egress);
- a stage whose authored or recorded capsule bounds exceed the node's
  `[node] *_ceiling` declarations;
- a `workspace_effect` stage on a run without `worktree_isolated = True` (the effect
  reads the recorded candidate the isolated workspace produces);
- a `dynamic_fanout` stage inside a `loop(..)` (`dynamic_fanout_in_loop_unsupported`);
- a `loop(..)` member or gate that lowers to a shape the oci member door cannot
  run inside an iteration (`loop_member_not_a_capsule_under_oci`): a body member is
  a shell or agent capsule (`Execute { Command | Agent }`), a static `topology(..)`,
  or a main-resolved `memory_snapshot()`/`workspace_effect` (resolved at the member
  seat on the head the earlier members applied); the gate stays capsule-or-topology
  only — a `sleep()` or `subworkflow` member, and any main-resolved class at the
  gate, is refused at CHECK rather than mid-run;
- a stage under a hard dollar bound (a `cost_budget("halt", ..)`, or a `cost_bound`
  — its own program's, that of any parent invoking it as a `subworkflow`, since the
  parent halts on a child's unmetered spend, or the `loop(..)`'s whose member or gate
  it is, since the loop's cost bound fails closed on a member of unknown cost) whose
  spend kata cannot price
  (`cost_bound_unenforceable_unpriced_adapter`: an adapter with no billing
  backend meters `Unavailable` under every credential mode; the one priced kind,
  `nanocode_anthropic`, serves no `subscription`, whose flat-rate spend carries no
  per-token price, and is refused under one `credential_mode_unsupported` first). A bound kata
  cannot measure is refused at CHECK rather than halted after the spend; the
  stage's tokens are still recorded, because the provider reports the usage itself;
- a `review_quorum` topology on the gate of a loop that authors a custom
  `gate_verdict` vocabulary (`loop_gate_quorum_needs_default_verdicts`) — use the
  default approve/refine/block vocabulary on that loop;
- a `review_quorum` topology on the gate of an `on_exhaustion = "accept"` loop with a
  `branch()`/`route()` on the loop's verdict field that has no `refine` arm
  (`loop_accept_quorum_route_needs_refine_tag`) — an accepted exhaustion under an unmet
  quorum routes `refine`; add the tag and its arm, or use another `on_exhaustion`.
  The refusal is judged again when a node recovers in-flight executions: one of this
  shape admitted by an earlier build fails that recovery closed, naming the stage, so
  let such runs finish before upgrading;
- a NON-agent stage that declares `cache_policy = "model_reuse"` — the capsule route
  serves the regime only for an agent capsule (see "The capsule model-reuse cache"
  below); a shell stage that wants caching uses `content_cache`;
- a `sleep()` whose deadline the main cannot store (below).

A check that runs with no node installed — `kata check`, `kata workflows check --all`,
`kata build` on a box with no booted node — cannot know the node's own answers, so
the arms that read them DEFER rather than refuse or guess. Each deferred class has a
name:

- `agents` — the `[agents]` declarations: adapter and credential pairings, the env
  door, pricing, and the `cost_bound_unenforceable_*` arms that depend on them;
- `ceilings` — the `[node] *_ceiling` declarations, the authored `output_bytes` /
  `work_delta_bytes` / `work_delta_entries` triple and the recorded `capsule_*` pair: an
  operator may raise or lower each, so no stage is judged against the shipped defaults;
- `egress` — `[node] egress_allow`;
- `environment` — the bound environment's `PATH` programs a `requires = [..]` names.

The report names exactly the classes it skipped, in one line —
`note: not judged without a booted node: agents, ceilings, egress — a booted node judges
them at admission; --config <kata.toml> judges all but environment` — and `--format json`
lists them as `deferred_node_facts`. A class the check judged is never named, and one it
skipped is never silent. `--config <kata.toml>` installs that config's facts, so the
same check judges `agents`, `ceilings` and `egress` as that node would; the
environment's programs are resolved from the node's store at boot, so a `--config`
check still names `environment` when a stage `requires` a program — `note: not judged without a booted node: environment — a
booted node judges them at admission`, with no pointer back at `--config`. The same pack on a
booted node is refused by name at CHECK/admission. Every other arm above judges the
pack alone and still refuses — the installed `[containment]` policy among them: the
only stage it refuses, a model stage with `sandbox = "host"`, every check refuses as
`host_sandbox_unsupported_under_oci`, so it is not a deferred class.

A `topology(..)` stage runs under `oci`. Member 0 is the root, each declared child a
container of its own, and the stage settles with one fan-in envelope. Each member
writes its own copy of `/work`; the settle merges the members' changes, and two members
changing one path differently fail the stage with `work_fanin_conflict` rather than one
silently overwriting the other. A topology inside a `loop(..)` fans out on EVERY
iteration, gate included; on the gate, an unmet review quorum makes that iteration a
refine with the quorum's reason appended to the feedback. A `dynamic_fanout` topology
runs too: its root's output names the children (`child_invocation_requests`, checked
against the declared roles), each child runs with its
request's prompt under a header naming its role and owned paths, and under
`mutation_policy = "owned_paths"` a child that changes anything outside its own paths —
or the root, or a non-owning child, outside all of them — fails the stage before any
change lands. The scope is read off each container's recorded `/work` change set, and a
child whose own output requests children fails the stage `dynamic_fanout_nested`.

`approval = True` is honoured (see "Approval gates on `oci`"), and so are a blocking human
request (see "Blocking human requests on `oci`"), `cache_policy = "content_cache"` (see
"The capsule content cache") and a `loop(...)` (see "Review loops on `oci`") — a loop's
members pass the same check as any other stage, so a loop over a member some arm above
refuses is refused by that arm's name. A `subworkflow()` child's own stages must pass
the same check, so a child with a model stage refuses its parent.

There is nothing to fall back to. A workflow runs only on the installed main (`kata
serve`, then `kata run <workflow> --submit`): the capsule route opens the node's planes
from disk, and `kata run` has no daemon-free face — it takes no `--scratch` and no
`--config`, and clap refuses either at parse.

A node must declare the Nix closure its containers see. `kata init` does not write
`environment`: it is a machine fact init cannot invent — so a fresh `kata init` config
refuses boot `node_environment_undeclared` until you declare one, and the recovery
is exactly to write the declaration and boot again (init does seed
`[agents.default]` for the capsule route: the embedded harness, `adapter =
"nanocode_openai"` on kata's own login, `credential = { mode = "subscription", source =
"kata_login" }`, which `kata login openai` then fills, with `model = "gpt-6-luna"` and
`reasoning_effort = "medium"`; `kata init` takes no `--agent`). The block to write:

```toml
[node]
[node.environment]
label = "busybox-getent"
system = "x86_64-linux"
nixpkgs_attribute = "nixpkgs#pkgsStatic.busybox"
store_paths = ["/nix/store/…-busybox-static-…", "/nix/store/…-getent-…"]
path_prepend = ["/nix/store/…-busybox-static-…/bin", "/nix/store/…-getent-…/bin"]
integrity_policy = { verify = "nar_hash_only", sigs_needed = 0, required_signers = [], allow_unsigned_content_addressed = true, verify_contents_at_declare = true }
```

The store paths must already be realised in the host's store (`nix build --no-link
--print-out-paths nixpkgs#pkgsStatic.busybox`). Boot declares, verifies, roots and promotes
the closure before the node reports ready. An `oci` node without the key refuses boot
`node_environment_undeclared`. Declaring a different closure while the old one is active
refuses `node_environment_superseded` and prints the previous declaration. A capsule whose
program (`argv[0]`) is not on the closure's `PATH` is refused at authorization
(`capsule_program_not_in_environment`). A program named inside a `sh -c` script is the
closure's job to provide; kata does not parse the script. `GET /api/v1/system/status`
reports the state under `node_environment`: `bound` (with the `environment_id`) or
`none`. Both keys are read at boot only: a reload that changes either is reported as
restart-required.

A node may also bound the box a capsule may RECORD, on both axes:

```toml
[node]
capsule_memory_bytes_ceiling = 1610612736   # absent declares no ceiling
capsule_process_count_ceiling = 512         # absent declares no ceiling
```

Both keys are optional and have **no shipped default** — absent means the node declares no
capsule ceiling and `kata` never invents one (a shipped number would refuse ordinary
stages it was never consulted on). When a key is set, admission — and `kata check --config`
naming that config; a check with no node names `ceilings` unjudged — refuses any
stage whose recorded bound would exceed it — the recorded bound being exactly what
`capsule_assembly` writes: the authored `image.memory_mb` or the 512 MiB default,
for memory; the 64-process default, for `pids.max` (a nanocode kind's floors — 64
tasks, no memory floor — never raise either). The refusal,
`capsule_budget_over_node_ceiling`, names the bound and the knob.

### The agent environment

A nanocode stage (`nanocode_openai`, `nanocode_anthropic`; `kata init`'s default agent)
needs no closure of its own: its agent loop runs in the worker, and its capsule holds
only the tool host (`kata-toolhost`, bound read-only at `/.kata`) and the tool processes
the model starts. It binds the node environment, so the model's tools find busybox `sh`
(no bash), busybox's `grep`/`find`/`sed` (no `rg`), `git` and the CA bundle, and no
project toolchain: a stage whose commands need one declares an environment that carries
it. The capsule's budgets hold the tool host and every tool process together: 64 tasks
(nothing authors a process bound) and the stage's `memory_mb`, or 512 MiB when it
authors none. A model `exec_command` that does not say otherwise runs
a login shell (`sh -lc`), as nanocode declares; the capsule's rootfs carries no profile,
so it keeps the bundle's environment.

`[node] environment` carries no env-var key: a capsule's `process.env` on this route is
`PATH=<path_prepend>:/bin`, the egress plumbing's eight (`HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` and `NO_PROXY`, each in both casings) when the capsule declares egress, the
`[agents.<label>] env` declared non-secret map, and the `HOME` (`/tmp`) its
`kata-toolhost` init renders. A node
env may name none of the names kata itself renders — `PATH`, the plumbing's, `HOME` —
nor `XDG_RUNTIME_DIR`, which the worker keeps for its user-manager clients:
`Capsule::new` refuses the collision `capsule_agent_env_channel_owned`, naming the
channel that owns the name, CHECK refuses it at admission under the same name, and
`kata config check` refuses the block itself. The credential never enters the capsule:
the harness holds it in the worker's process. An `env:` key is in the worker's
environment and in none of the processes that run the capsule: the worker starts
`kata-provider-youki`, and the provider and the worker start each `youki`, with an empty
environment. The one exception is the throwaway container the worker runs once at its
start to certify youki: `systemd-run` needs `PATH` and `XDG_RUNTIME_DIR` to reach your
user manager, so that `youki run`, and the `systemctl --user kill` that stops it on a
timeout, keep those two — and neither can carry a key, since an `env:` source may not
name `PATH` or `XDG_RUNTIME_DIR`.

There is no operator `$HOME` grant: a capsule's HOME is the throwaway `/tmp` tmpfs and
ambient host state is not mounted.

Every nanocode turn ends before its outcome is recorded: the tool host kills every
process it started (or, over a broken wire or past a 5 s grace for its confirmation,
kills them itself on its stdin's close, which the outcome does not wait for), and the
harness is shut down within a second 5 s grace. Every Code Mode cell runs in an
interpreter process, a confined child of the process hosting the worker (always a
`kata-worker` — the node `kata serve` supervises, or a daemon you start; `ps` shows its
command name as `exe` and its command line as `/proc/self/exe --exact
kata_code_mode_interpreter ...`, a child of that process), and the
shutdown kills and reaps the interpreter of every cell it holds, so a cell inside one
long native step (a built-in sort of millions of elements) ends with it. A cell whose
interpreter crashes fails to the model naming the signal and is recorded in the
evidence as `code_mode_interpreter_ended`; the turn goes on. The interpreter's last
confinement step is a seccomp allow-list, on every one of its threads: a system call
outside the set it was measured to make ends it by `SIGSYS` (`code_mode_interpreter_ended`
with `SIGSYS` in the evidence means the interpreter tried one; with an honest cell it
never has, an interpreter stopped and continued, by job control, a cgroup freeze or a
suspend, included). This is a HOST REQUIREMENT of every nanocode turn: a Linux x86-64 kernel
that installs a seccomp filter with `SECCOMP_FILTER_FLAG_TSYNC` and the `kill_process`
action (`/proc/sys/kernel/seccomp/actions_avail`), and no enclosing seccomp profile that
refuses `seccomp(2)` to the worker. Where the filter cannot be installed, every Code
Mode cell fails naming why (`... could not confine itself: seccomp(2) refused its
syscall filter (...)`) and none runs; `just host-check`'s `code mode filter` row asks
the same of the kernel in seconds. The interpreter's standard error goes to the process
hosting the worker, not to its log: its last 64 KiB are kept per interpreter (earlier
bytes dropped and counted) and appended to the error of a cell its end fails, labelled
`its standard error since it started` since they may be an earlier cell's; that is
where a panic or glibc assertion line appears. What the turn's end
leaves is recorded: a completed turn's session evidence carries `turn_end`
(`kill_all`: `unconfirmed` or `wire_broken`, when the kill was not confirmed) and
`code_mode_workers_live` (the Code Mode workers live in the worker's process once
the shutdown returned or its grace expired, each until its interpreter process was
reaped: process-wide, other attempts' included, so `0` says none of this turn's
survived); a turn that did not complete names both in its refusal's reason instead
(`kill_all: unconfirmed ...` or `kill_all: wire_broken ...`, and a nonzero
`code_mode_workers_live: <n> ...`). That includes a turn the worker gives up on past
its stop grace: its turn end runs when the worker closes the session, after its
evidence is taken, and the close reports what it found. A turn a worker panic unwinds
records neither.

#### Agent model and reasoning effort under `oci`

`[agents.<label>] model` and `reasoning_effort` are NODE declarations the
turn spec carries — contract facts, folded into the capsule's reuse key when
present, so two turns differing only in either are different capsules and
never adopt each other's answer. `model` reaches the adapter as the turn's
model hint (a stage's own `model_hint` authoring wins over the node's
declaration). Both nanocode kinds require `model`: a turn naming none refuses
`agent_model_undeclared`, and nanocode's own default is never chosen.
`reasoning_effort` is an opaque pass-through spelling the model owns,
delivered as the harness's own thinking level, set on the agent before the
turn: a level nanocode does not name refuses `agent_effort_unsupported` before
any model call, rather than run the turn at a default the node never stated.
Declaring nothing sends nothing — the model's own default applies.

`nanocode_anthropic` bills against the built-in `anthropic` rows: an `api_key`
turn on `claude-fable-5-1`, `claude-mythos-5-1`, `claude-opus-5-5` or
`claude-sonnet-5-5` is `estimated` from Anthropic's list prices (input, output,
cache read, and the 5-minute cache write, each at its own rate — read off
Anthropic's pricing page 2026-11-02, dated `2026-11` on every estimate), any
other model at the unknown-model floor (`claude-haiku-5-5` is priced per
request's prompt length, which a turn's summed usage cannot state), and a
`subscription` turn is `Unavailable`. `nanocode_openai` has no billing backend:
every turn of it is `Unavailable` with its tokens kept, under `api_key` as
under `subscription`, so a hard dollar bound over it refuses at CHECK
(`cost_bound_unenforceable_unpriced_adapter`), and a `[[pricing.models]]` row
does not price it. A `token_bound` holds over either kind (both report every
token class), as do a `time_bound` and the capsule's wall, and the tokens stay
on the record.

#### A stage's `produces=` contract as the turn's output schema

An agent stage that declares `produces = contract(..)` is validated against
that contract when its answer comes back, and retried up to `validate_retries`
times when the answer fails it. On an adapter whose protocol carries one, the
same contract is ALSO sent to the model as a strict structured-output JSON
Schema — every property required, `additionalProperties: false`, only the
keywords that mode admits — derived from the contract kata validates against,
never written a second time:

- `nanocode_openai`: nanocode's strict `json_schema`
  `text.format`, on every Responses request of the turn.

`nanocode_anthropic` has no such channel (nanocode's Messages client carries
none); its turns are sent no schema, and the contract reaches the
model through the prompt alone (`json_only(json_skeleton(..))`). The schema is
an aid: kata's own validation stays the only judge of the answer, on every
adapter.

A flat `outputs = {..}` table is not a contract: it is checked the same way,
but it is sent to the model on no adapter, and the prompt kata renders is the
authored one with nothing about it added (only a validation retry's prompt gains
the validation error). A prompt over one states the answer's shape itself.

The strict schema differs from the contract in four stated ways:

- an optional field (`required = False`) is sent required-and-nullable, and
  kata reads a `null` on an optional `produces=` field as the field being
  absent — it is removed from the parsed output on every stage that declares
  a contract (agent on any adapter, and shell), so `stages.<id>.parsed` is the
  same document whether or not a schema was sent (a `workflow(params=)` field
  has no such reading: a `null` param is checked against its type);
- `min_length`, `max_length` and `pattern` on a string are not sent as
  keywords (the length keywords are not admitted by strict mode, and its
  pattern dialect is not kata's); each is restated in the field's
  description, and kata still enforces it;
- strict mode's `integer` admits `3.0`; kata's does not;
- fields are sent in NAME order, not the order the contract declares them (the
  lowered contract keeps no declaration order; the prompt's `json_skeleton`
  does). A schema-constrained model writes the fields in that order; no answer
  is accepted or refused on account of it.

A contract with no fields — the arms of `variant({"ship": contract("Ship", {}),
"hold": contract("Hold", {})})`, kata's typed-routing idiom — is sent as the
closed empty object (`properties: {}`, `required: []`), which accepts only `{}`
exactly as kata does; the provider's acceptance of that spelling is not
measured on a model turn. A contract strict mode cannot state is sent as no
schema at all, never as part of one: more than 5000 fields, 1000 enum values or
120 000 characters of names and enum values across the contract. The stage then
runs on the prompt path, and the main logs the reason at `info` when it assembles the capsule.

#### Agent credentials

**kata's own login (`kata_login`) is the embedded harness's credential.** A
nanocode agent (`nanocode_openai`, `nanocode_anthropic`) declares
`credential = { mode = "subscription" | "api_key", source = "kata_login" }` (or an
`env:<VAR>` API key), and must declare one: a nanocode block with no `credential` is
refused `credential_undeclared` at check, at capsule assembly and by the worker before
the container, and `kata doctor`'s `agent_backends` row fails it. kata never reads
another tool's login: a `credential.source` other than `kata_login` or `env:<VAR>` is
refused `credential_undeclared`, naming the two admitted spellings, at check and at
capsule assembly, as is an `env:<VAR>` naming a variable kata's own plumbing holds
(`PATH`, `HOME`, the eight proxy names, `XDG_RUNTIME_DIR`), and by `kata config check` and `kata doctor`'s `agent_backends` row —
the config load accepts the spelling, so only the stages that select the block are
refused. A `[node] host_logins` key is refused at load, as an unknown field. The login
is a file kata
writes on an explicit operator command, in ONE owner-only directory under the effective
owner's home (the account record's home, never `$HOME`, so the installed service, the
CLI and a `kata-worker` daemon of one uid read the same files):

| command | file in `~/.config/kata/logins/` | serves |
|---|---|---|
| `kata login openai` (`--device-code`, `--browser`, `--no-browser`) | `openai-chatgpt.json` (+ `.lock`) | `nanocode_openai`, `mode = "subscription"` |
| `kata login openai --api-key` | `openai-api-key` | `nanocode_openai`, `mode = "api_key"` |
| `kata login anthropic --api-key` | `anthropic-api-key` | `nanocode_anthropic`, `mode = "api_key"` |

`kata login openai` logs in to ChatGPT by one of two flows, which store the same
`openai-chatgpt.json`:

| flag | flow |
|---|---|
| (none) | the device-code flow when the session is remote (`SSH_CONNECTION` or `SSH_TTY` set) or has no graphical display (neither `DISPLAY` nor `WAYLAND_DISPLAY` set); the browser flow otherwise. An empty variable counts as unset. |
| `--device-code` | the device-code flow |
| `--browser` | the browser flow, opening a browser |
| `--no-browser` | the browser flow, printing the URL without opening a browser |

Any two of the flow flags, or one beside `--api-key`, refuse naming both. The
**device-code flow** is OpenAI's ChatGPT device authorization: kata prints a URL
(`https://auth.openai.com/codex/device`) and a one-time code to enter there on any device,
polls the issuer at the interval it states, and stores the login once the code is
approved; it needs no port forward, so it is the flow for a remote host over SSH. Until
the approval no file is written — a refused, expired or interrupted (Ctrl-C) login writes
no file and leaves an earlier login as it was (an absent logins directory is at most
created, empty) — and it refuses by name:
`device_code_not_enabled` when the issuer answers the code request 404 (codex reports
this as "device code login is not enabled for this Codex server. Use the browser login or
verify the server URL."; use `--browser`), `device_code_refused` naming any other error
status and the step, `device_code_expired`, `device_code_interrupted`. The **browser
flow** prints the ChatGPT authorization URL (and opens a browser unless `--no-browser`),
waits five minutes for the callback on `localhost:1455` (or 1457) and stores the login;
on a remote host it needs the port forwarded first (`ssh -L 1455:localhost:1455
<host>`). Log in on each host — never copy the file between hosts, because each refresh
rotates its refresh token. `--api-key` reads the key from
stdin, never the command line, and refuses a terminal (it would echo the key): `kata
login openai --api-key < key-file`. `kata login status` reports each file offline
(present, owner-only, its kind, the access token's expiry, whether a refresh token is
stored). `kata login status --check` also checks each stored file with ONE authenticated
read that spends nothing — an API key against its provider's model list
(`api.openai.com/v1/models`, `api.anthropic.com/v1/models`), the ChatGPT login against the
ChatGPT backend's usage read after the same pre-turn refresh a turn makes — and reports
each `ok`, `refused` (the provider answered 401 or 403, or the file is refused offline),
`expired` (the ChatGPT access token is past its expiry and its refresh did not renew it)
or `unchecked` (no answer, or a status that judges no credential); any stored login that
is not `ok` fails the command. Only the answer's status is read. `kata logout <provider>` removes that provider's files (the issuer is not
told), and with them any temporary copy a crashed write left (`.<file>.<pid>.<ms>.tmp`,
also removed by the next write of that file) and, for `openai`, the staging file
`openai-chatgpt.login.json` a killed browser login left (also removed by the next browser
login). kata has no Claude subscription login in this build: `nanocode_anthropic` under
`mode = "subscription"` cannot run, and is refused `credential_mode_unsupported` at check
(under any source, before the opt-in and hard-dollar doors) and at capsule assembly.
`kata doctor` fails it naming that door; use `kata login anthropic --api-key` and
`mode = "api_key"`.

The worker reads the file for the agent's provider and declared mode, and nothing else,
before the container exists. The directory must be a real directory owned by you with no
group or world bits, and the file a regular single-link file owned by you with no group
or world bits; anything else refuses `credential_unavailable` naming the path (kata
repairs nothing). A mode refusal ends with the command that fixes it (`fix: chmod 700
<directory>`, `fix: chmod 600 <file>`, the path shell-quoted); a path another account
owns is refused with the reason and no command. The check covers that directory and its
files, not the directories above it: `kata login` creates any missing one mode 0700. An
absent file refuses too, naming the `kata login` command that writes it. A ChatGPT
access token inside nanocode's early-refresh window (five minutes of its expiry at the
pinned nanocode rev) is refreshed there, by kata, through nanocode, and again on a 401
mid-turn; every refresh holds the store's
`flock` from before the token request until the rotated tokens are written, and one that
finds the token already rotated adopts it instead of presenting a stale one, so turns in
one process or in several rotate the login exactly once; a refresh waits at most 60 s
for another holder's lock, then refuses. An access token already past its expiry that
the refresh could not renew refuses `credential_expired` naming `kata login openai`; one
still unexpired is used, and refreshed again mid-turn. A worker process that dies
between the issuer's answer and the write loses the rotation, and the next refresh is
refused: log in again. A process that cannot resolve the effective owner's home (no
account record, a home that is missing, a symlink or another uid's) still starts; each
`kata_login` turn it runs refuses `credential_unavailable` naming why.

**API-key agents under `kata serve`.** A `kata serve` started from a shell starts
its supervised node in that process's environment: the node reads `<VAR>`
for an `env:<VAR>` agent from the environment `kata serve` was launched with,
plus what `.env` added. kata loads at most ONE `.env`: dotenvy takes the first
`.env` it finds walking up from the current directory, and never overrides a
launch value. A project set up with `kata host setup` has its own `.env` at its
root (the provider exports), so a key kept in another directory's `.env` is not
loaded for that project. Put `<VAR>` in the launch environment, scoped to the
command, from wherever the key is kept (it is loaded, never printed):

```sh
( set -a; . <file holding VAR=…>; set +a
  kata doctor --config .kata/kata.toml    # [pass] credential_env … `<VAR>` is set
  kata serve --config .kata/kata.toml )
```

`kata doctor`'s `credential_env` row reads the same environment the serve
beside it inherits, so run it in that subshell: `[warn] credential_env … are
unset in this environment` is the refusal (`credential_unavailable`) a worker
started from it would reach. The worker also refuses `credential_unavailable`,
before the container and naming the variable, a value that is not UTF-8 and a
value no HTTP header carries, because the embedded harness sends the key as a
header. The row judges the value by the same rules and reports `[fail]
credential_env`, naming the agent and the variable and never the value, for
exactly a value that is not UTF-8, or one holding a control character other than a tab (a byte below 0x20, or 0x7F — as a
key exported with its trailing newline has), judged with the worker's own
predicate. An empty, spaced or non-ASCII value passes: it is a header value, and
the provider answers it. A launch value that is
not UTF-8 stays the variable's value: `.env` replaces it no more than any other.
A `KEY=…` line in the project's own `.env` also works; starting `kata serve`
from inside another checkout so that checkout's `.env` is found loads every
other variable that file declares as well, so do not rely on it.

**API-key agents under `kata service install`.** An installed main does not
run in your shell: it runs under the owner-only environment snapshot the
install wrote (under `~/.config/kata/service-environments/`), and the node it
supervises inherits that environment and reads `<VAR>` from it. So for every `[agents.<label>]`
declaring `mode = "api_key", source = "env:<VAR>"`, `kata service install`
copies `<VAR>` from the environment it runs in into the snapshot and records it
as declared; the value never enters the unit file. The install refuses, naming
`agents.<label>.credential.source` and the variable, when `<VAR>` is unset, is
set to a value that is not UTF-8 (said so: the snapshot holds text), is not a
valid name, is in kata's reserved `KATA_` namespace, or is a name the
worker never delivers a credential through (`PATH`, `HOME`, the proxy
variables). The key is the value at install
time: to rotate it, stop the service, export the new value, re-run `kata
service install --config <path> --apply`, then start the service. A main configured
with no `supervised_node` transport starts no node, so the install neither copies nor
requires these variables: export them to the environment of each external
`local_socket` worker instead.

Capsules are placed only on a live worker that holds certified containment. Otherwise
the submit is refused `no_oci_worker_available`.

**The node is always a separate process.** The main hosts no worker: capsules and the
agent harness (its loop, its model connections, its Code Mode interpreters) run in a
`kata-worker` process. `[[workers.transports]] type = "supervised_node"` — what `kata
init` writes — makes `kata serve` start one beside it: it binds `<data_dir>/node.sock`,
renders the node's `node.toml` and `node.cred` (the local enrollment secret) into the
data directory at every boot, starts `kata-worker run --config <data_dir>/node.toml`
from beside the running `kata` (refused `supervised_node_binary_absent` when it is not
there), and publishes readiness only once that node enrolled; a node that ends before it
enrolls, or has not enrolled 180 s after it started, fails the boot, its own refusal
printed on the main's stderr, which the node shares. The node's durable membrane store
is the data directory's `idempotency.db`. When the main's cgroup is delegated (as under
`kata service install` or `systemd-run --user --scope -p Delegate=yes`), the main moves
itself into `<cgroup>/kata.main` and starts each node in a fresh `<cgroup>/kata.node`;
when a node ends, the main kills that subtree (`cgroup.kill`), waits for it to empty and
removes it, so no capsule process outlives its node, and starts a new node after a pause
(1 s, doubling to 30 s while nodes keep ending early). The main settles the dead node's
attempts as it settles any worker's death: PROVEN AMBIGUOUS once a capsule was
delivered, never re-run. A node that stops answering without ending (stopped, or hung)
is judged dead once its heartbeat grace passes; before its attempts settle, the main
kills it with its whole `kata.node` subtree (`cgroup.kill`; only the node's own process
when the main's cgroup is not delegated), waits for that subtree to empty, and records
the kill in each settlement's reason, then starts a new node after the same pause, which
enrolls afresh: a stopped node never resumes on its old connection. A node started again
that has not enrolled 180 s after it started (stopped or hung before it dialed, so no
heartbeat can judge it) is killed the same way and replaced. An operator's `kata-worker`
daemon judged dead is settled on its silence and left running. The node never loads a
`.env` of its own: it inherits the main's environment, which already holds what the
main's own `.env` load added (nothing, under `kata service install`). The node binary is
found by path at every start, not pinned like the main's: rebuilding kata while a main
runs makes its next node a `kata-worker` of the new build under the old main (see "Run
workers from the same build as the main" below). `type = "in_process"` is refused at
load, `worker_transport_in_process_removed`, naming both transports that exist.
`kata-worker` daemons you start yourself dial a `local_socket` transport, beside the
node or instead of it. `workers.max_workers` counts every worker the main admits: with a
`supervised_node` transport one slot is the node's own, taken only through `node.sock`,
and every `local_socket` path shares the rest, so the main closes a daemon's connection
past that share (logging `local worker refused: capacity limit reached`) and no daemon
takes the node's slot (a config whose `max_workers` is too small for one of each is
refused at load). A `kata-worker` daemon must name `main_data_dir`, the main's data
directory, in its own config file: it opens that directory's `operational.db` and
`cas.db` READ-ONLY to resolve a capsule's environment and input trees, and publishes
each result tree into its `cas/`. A daemon whose config names no `main_data_dir` refuses
to start `worker_main_data_dir_undeclared`.

```toml
# kata-worker config
main_data_dir = "/home/you/.local/share/kata"
```

A worker heartbeats at the cadence its MAIN sets, never one of its own: half the main's
`[workers] heartbeat_interval_ms`. The main binds that interval into every worker's
enrollment, its supervised node's and each daemon's (covered by the enrollment proof), so
the main's liveness deadline is always measured against a cadence it chose. A `kata-worker` and a
main of different enrollment versions refuse each other at enrollment.

**Unix socket paths and the data directory's length.** The kernel limits a unix
socket address to 108 bytes, but kata never hands it a socket's full path: the main's
`local_socket` listener (`<data_dir>/<name>`), a worker's connect to it, and an `Egress`
capsule's handoff socket
(`<data_dir>/oci-worker-state/attempts/<attempt>/egress/handoff.sock`, bound by the
worker and connected by `kata-oci-hook`) are each addressed as
`/proc/self/fd/<fd>/<name>` through a descriptor on the socket's directory. So the
108-byte limit no longer depends on `[node] data_dir`'s length (the `change` pack's PR
cell is proven live under a 200-byte `data_dir`); the kernel's other path limits, such
as `PATH_MAX` (4096 bytes) for every path under the data directory, still apply. The
one socket bound left is the socket's FILE NAME: at most 82 bytes. A `local_socket` `path` or a worker's
`home_node_endpoint` whose file name is longer is refused when the config loads, by
`kata serve`, `kata doctor` (`config_validation`) and `kata-worker` alike, naming the
limit and the path.

`[workers] assignment_start_deadline_ms = 0` is refused at load
(`capsule_start_deadline_disabled`): the start deadline is the only leg that settles a
capsule delivered and never started, so it cannot be switched off.
`[workers] heartbeat_interval_ms = 0` is refused at load too
(`heartbeat_interval_disabled`): it is the period of the main's heartbeat sweep and of its
deadline sweep, and neither can tick at zero.

The process that runs the worker (always a `kata-worker`: the supervised node, or a daemon you start) also needs
the OCI provider, `kata-provider-youki`, installed into a by-hash provider store.
`kata sandbox install-external-provider --name youki <dir>` prints the three exports:
`KATA_EXTERNAL_PROVIDER_STORE`, `KATA_EXTERNAL_EXECUTION_PROVIDER=youki` and
`KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS`. The worker checks these at start, in this order,
and refuses to start by name at the first that fails:

1. `oci_provider_undeclared`: no provider is declared.
2. The provider store refuses the entry.
3. `capsule_planes_unreadable`: the node's planes do not open.
4. `oci_route_uncertified`: the pinned youki cannot be certified on this host.

Only the last step starts a (throwaway) container. A `kata-worker` daemon makes these
checks before it connects to its main.

A capsule's container has no network route: its network namespace holds a loopback
interface and nothing else. A capsule may declare an egress allowlist — exact
`host:port` authorities — and for those, the container's proxy variables
(`HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, each also lowercase, since curl reads only
`http_proxy` for an `http://` URL) point at a proxy endpoint the WORKER owns: two
runtime hooks raise the guest's loopback and hand the listening socket out of the
namespace to the worker, which accepts the
guest's `CONNECT` requests there. The worker resolves each allowlisted name itself,
refuses any whose addresses are loopback, private, link-local (including cloud instance
metadata), shared/CGNAT, multicast or other special-purpose space — an IPv6 address in
one of the well-known forms that carry a v4 one (v4-mapped, IPv4-translated, the
well-known NAT64 prefix `64:ff9b::/96`, 6to4) is judged by the v4 address it carries
(`egress_address_refused`); a network-specific NAT64 prefix (RFC 6052) or an ISATAP
address hides where its v4 sits and is judged as IPv6 only — and connects only to the
addresses it checked. A CONNECT to an unlisted authority is refused `403` and
recorded as `host_not_allowed` on the attempt's evidence; a hook binary whose bytes
moved from the provisioned pin is `hook_digest_mismatch`. The provider entry must carry
the `kata-oci-hook` and `ip` members the mechanism execs — an entry provisioned without
them refuses an `Egress` capsule `provider_unresolved` before the container starts, so
an egress-bearing deployment re-provisions its provider with those members in the
source directory. `install-external-provider` copies only the directory it is given,
and the package's `share/kata/provider-source` does not hold `ip` (`kata host setup`
adds it from the declared store path). Give `install-external-provider` a directory
holding all four: a copy of `share/kata/provider-source` plus the `ip` file named by
`share/kata/provider-members.toml`. For a checkout build, the first three are
`target/release/kata-provider-youki`, `target/release/kata-oci-hook` and, as
`toolhost/kata-toolhost`, `target/x86_64-unknown-linux-musl/release/kata-toolhost`,
and the `ip`
is the one named by the `share/kata/provider-members.toml` of the checkout's
`nix-build nix/share.nix` (which `kata host setup` roots at
`.kata/nix-roots/kata-share`).

The allowlist a stage reaches is declared two ways. A shell or agent stage whose
sandbox profile authors `net = "host"` reaches exactly the node's `[node]
egress_allow` — a list of exact `host:port` authorities, each checked at config
load (a misspelled entry refuses the boot, naming `node.egress_allow` and the
entry):

```toml
[node]
egress_allow = ["api.example.com:443", "mirror.corp.example:8443"]
```

An agent stage's capsule follows the same rule: the embedded harness's model calls
leave from the process hosting the worker, never from the capsule, so its block has no
`egress_extra` (the config load refuses one as an unknown field) and its capsule is offline
unless the stage authors `net = "host"`, which reaches exactly the node's `[node]
egress_allow`. A stage that authors no `sandbox=` — shell or model, and an API agent
run (`POST /api/v1/agents/run`) that omits `sandbox` or sends `{}` (each field of its
`sandbox` defaults to `oci` / `workspace_ro` / `offline`, and a request equal to that
default is the omitted field) — materializes to `sandbox_profile()`, whose `net` is
`offline`. `net = "offline"` is the spelling for no node-provided egress — so under
`oci`, `kata check` refuses a `net = "host"` stage on a node whose `egress_allow` is
empty (`egress_undeclared`), rather than silently minting an allowlist that names
nothing.

Every face states what each capsule's network IS, as a posture — `offline` or
`egress` — with its exact authorities:

- `kata check --config <kata.toml>` prints a `capsule_network:` block, one line per
  capsule a stage can run (`- review (agent reviewer): offline`, or `- fetch: egress
  (index.crates.io:443)` for a `net = "host"` stage). An agent stage gets one line per
  agent it can run under: the primary, then every fallback panel member a failure
  retry advances to. `kata workflows inspect` prints the same rows per stage;
  `--format json` and REST `GET /api/v1/workflows/{name}` carry them as
  `preflight.stages[].capsule_networks` (`{agent, network}`), and the `check`
  operation (`kata check --format json`, MCP, REST `/ops/check`) as `capsule_networks`
  (`{stage, agent, posture, allowlist}`). This is a prediction from the installed node's facts — the same rule
  assembly mints from at dispatch, but a node whose configuration changes before
  dispatch mints from the new facts; with no node installed it is absent, its facts
  deferred.
- `kata run show <exec-id>` and REST `GET /api/v1/executions/{id}` list
  `capsule_networks`, one row per declared capsule — `{stage, capsule_id, network}`
  read off the capsule's own bytes, so the record states what the capsule GOT even if
  the node's configuration changed since; the `observe` operation carries the same
  rows as `{stage, posture, allowlist}`.
- An approval gate's capsule (REST `/api/v1/approvals`, `kata approvals`) carries
  `capsule.network`, the network approving it authorizes, off the same bytes.

The checked program's per-stage class (`preflight.stages[].execution_class`) never
claims an `offline` network for a model stage: its turn talks to its model provider,
so its network axis is `unrestricted` under either `net`, and a model stage that declares
`execution_requirements = {"network": "offline"}` is refused at check under every
`net` (declare `"unrestricted"` or drop the key).

A capsule attempt that the main loses sight of is settled terminal and not re-delivered:

- after a worker death. A worker whose connection closes (its process exited) is dead at
  once. A worker whose connection stays open is dead past `heartbeat_interval_ms +
  heartbeat_grace_ms` of OBSERVED silence, counted from its last heartbeat or, before its
  first, from when its main started reading it: it heartbeats every half interval, the main
  sweeps every interval, and each sweep charges at most one interval of silence, so a
  stall that holds up the main's sweep (its whole runtime blocked on a slow disk, a CPU
  it could not get, a stopped process) counts as one interval however long it lasted. A
  stall that holds up only the reading of a heartbeat while the sweep runs on time (the
  worker's result reactor blocked in a durable write on one of the main's threads) is
  charged in full, as a delay of that heartbeat. A live worker is therefore never settled
  dead while each heartbeat is delayed by less than `grace - interval / 2` on top of any
  stall of the sweep (`grace + interval / 2` when the sweep does not stall): 4.5 s and
  5.5 s at `1000`/`5000`, 25 s and 35 s at the default `10000`/`30000`. A worker that
  stops heartbeating is found dead at the first sweep past the deadline: within one
  interval of it while the main's sweeps run on time, later by each stall of the sweep
  beyond one interval. That bounds the verdict; the settlement's durable writes land
  after it, later still on a slow disk. A dead worker is settled again at every sweep
  until it heartbeats, so an attempt placed on it after its verdict is settled at the
  next sweep, and a settlement that failed is retried there — until its connection is
  gone and a sweep's settlement leaves no attempt on it, when the main forgets it and
  judges it no more. `heartbeat_interval_ms = 0`
  and a `heartbeat_grace_ms` shorter than `heartbeat_interval_ms` are refused at load
  (`heartbeat_interval_disabled`, `heartbeat_grace_below_interval`). The heartbeat is the
  worker loop's own task, so it keeps beating while a turn hangs; a hung turn is bounded
  by its wall time below, not by this leg. The settlement's recorded reason names the leg
  and its evidence — `worker <id> died: its connection closed (<the transport's reason>)`
  or `worker <id> died: no heartbeat for <s> s of observed silence, past its <s> s deadline
  (the last one <s> s ago)` — then what `/proc` said of the worker's process at that
  moment (`its process <pid> exists in state <S>`, or `is gone`), the pid being the one the
  kernel reported for the worker's connection;
- past its promised wall time plus a 150 s grace, measured from its recorded start. The
  grace is sized so a live worker's own kill of the container is issued at least 30 s
  before it: the worker refuses to hand a container to the runtime more than 90 s after
  it reported the start, and kills it once its wall time plus 30 s has passed since that
  hand-over. It orders the KILL, not a success: a stage
  that finishes just inside its wall time has only those 30 s to publish its output and
  report, and a later report is superseded. It also assumes the two clocks agree — a
  suspend of the worker's host, or a step of the main's wall clock, shortens the grace by
  its size;
- when delivered but never started: once `assignment_start_deadline_ms` plus 60 s has
  passed since the LATER of its dispatch and the moment its worker's slot last freed
  (the last time an attempt that started on that worker finished), and only while that
  worker holds no live started attempt. A capsule queued behind a running one is waiting,
  not lost, and is never settled by this leg; the running one is bounded by its own wall
  clock, and the queue is measured again from when it frees the slot. Every part of this
  is re-read under the database's write lock at the moment of settlement, so a start
  the main has already recorded by then is never recorded as "did not start" (one still
  in flight to the main is not seen, and the fenced stop the main then sends refuses its
  launch or kills its container);
- when the main's send of its frame is still pending `dispatch_deadline_ms` after it
  began, the attempt has no recorded start, its worker holds no live started attempt, and
  at least `dispatch_deadline_ms` has passed since the LATER of its dispatch and the moment
  that worker's slot last freed — the start-deadline leg's premise with the dispatch
  deadline as its window, re-read under the write lock. The write is not cancelled (a
  half-written frame would desync the connection), so the frame may still arrive, and the
  main sends a fenced stop. A send pending behind a running attempt is backpressure: the
  main stops waiting at the deadline, the attempt stays dispatched, and the write finishes
  on its own (a send the transport then refuses is settled as the next leg says). A send
  whose own task ended without an answer (it may have written part of the frame) is
  settled at once;
- when the main could not build its frame, or the transport refused it;
- when it was claimed and never dispatched: its authorization failed after the claim, or
  its execution reached a terminal outcome first (checked every sweep tick and at start).
  A claim the main died before dispatching, in a run that is still running, is not
  settled: the restarted main dispatches that same attempt once when it resumes the run,
  and settles it this way, failing the run, only if that dispatch cannot be made (no
  worker is registered, for one);
- when the main refused its result;
- when the main restarted with the attempt in flight; the recorded reason opens
  `the main restarted`. A failure the attempt's worker reported, which the previous main
  had stored but not yet recorded when it died, is recorded first, as the worker reported
  it (its verdict, its reason and any provider failure), and the attempt is then not
  settled this way — unless that recording cannot be made (the stored report cannot be
  read or is refused, or the restart's 30 s budget for these reports runs out), when the
  attempt is settled with that reason, PROVEN AMBIGUOUS. A restart settlement under a standing
  stop records the attempt cancelled, not failed
  (`Dispatcher::settle_capsule_attempts_after_restart`).

The recorded reason says PROVEN NOT PERFORMED only when no frame for the attempt can have
reached a worker: the frame could not be built, the transport refused it, or the attempt
was never dispatched (a frame is sent only after its dispatch is recorded). Every other
settlement says PROVEN AMBIGUOUS, because the main cannot see whether the container ran. A worker that cannot report a capsule's start launches nothing. A main
installed with `kata service install` runs with `Delegate=yes` (its capsule containers'
`memory`/`pids` bounds need a delegated cgroup) and `KillMode=control-group`, so a main that
dies takes its supervised node and the node's containers with it; the next main settles their
attempts, and the capsule route of the node it starts reclaims their attempt directories when
that node starts. It runs under the owner-only
environment snapshot the install took, never your shell's environment: a bounded set of host
variables, the provider declaration `kata host setup` writes (see "Preparing a host and
project for `oci`"), any `api.auth.verifying_key_env` (named outside the reserved `KATA_`
namespace, which the main refuses at load), and, when the main supervises a node, every
API-key agent's `env:<VAR>` (see "Agent credentials").

To retire an environment, stop the main first:

```console
$ kata service stop --apply
$ kata node environment release <environment-id> --config <path>
```

The release is refused `node_environment_release_requires_stopped_main` while a main holds
the discovery lease or the data-directory lock. It is refused
`environment_bound_to_live_attempt` while any live attempt's capsule binds the environment.
That includes an approval gate still waiting for a decision (below).

### What runs in the main under `oci`

The constructs below run no container. The main records each one's outcome once, as the
accepted outcome of that stage's (or route's) own operation, and `kata run show` reads it
back from there.

**The `parallel()` join.** The main resolves the join once every branch it fans in has
completed, and `kata run show` reports its output as `{"joined": [<branch occurrence ids>]}`.
Each branch
edits its OWN durable `/work` head — forked off the single point all the barrier's
siblings share — and the join fans the branch deltas into the parent's: paths only one
branch touched land, identical writes collapse, and the parent's own edits to paths no
branch contested carry through. A pack whose fan-in reads files its branches wrote
(`parallel-smoke`, `fanout-merge`) gets exactly that merge. Two writers giving one path
different content — two branches, or a branch and the parent's own move since the fork —
fails the join `work_fanin_conflict` with the contested paths and the branch labels
named, and moves no head; the failed join is recorded once and re-runs converge on it.
The same applies to every main-resolved failure under `oci` — a `work_fanin_conflict`,
a `work_delta_base_stale`, a refused `workspace_effect`: `kata run show` reports the
recorded reason in `error` (`stage <stage> failed: <reason>`), read back from the
attempt's durable transition.
Fan-in through outputs (`{{ stages.<branch>.parsed.<field> }}`), as
`workflows/smoke/join-outputs-smoke.star` does, is unchanged.

**`branch()`.** The route's decision is recorded ONCE, as the accepted outcome of the
route's own operation (a main-resolved attempt whose stage id is `#op/<path>`), and `kata
run show` lists it under `routing` as `{condition, taken, not_taken}`. The not-taken arm is
skipped and never runs. A route whose verdict matches no arm fails the run (`select_verdict_unmatched`), which a
checked pack cannot reach. After a restart the recorded decision is re-read, never re-made,
and a recomputed decision that disagrees with it stops the run (`select_decision_diverged`).
An authored stage id may not contain `#` (`stage_id_reserved_character`).

**`sleep()`.** The main parks the stage on a durable deadline — `for_ms` after the instant
the sleep was claimed, or `until_ms` — and the deadline sweep completes it with
`{"deadline_ms": <deadline>}`. Expect the wake up to one `[workers] heartbeat_interval_ms`
(default 10 s) AFTER the deadline, never before it. The deadline survives a restart of the
main unchanged: a restart before it waits, one after it completes the sleep once, and a
deadline that passed while the main was down fires as soon as startup recovery finishes
rather than a heartbeat later. `for_ms` is bounded at one year and `until_ms` at the largest
instant the plane stores; `kata workflows check` refuses a longer one
(`durable_sleep_unrepresentable`). A clean shutdown of a main whose runs wait only on sleeps,
unanswered blocking human requests or subworkflow children does not wait for them: the runs
resume from the chain at the next start.
`workflows/smoke/sleep-smoke.star` exercises it.

**`subworkflow(pack = ..)`.** Its child program is the one bound at check (top of this
guide). The child runs as a SEPARATE execution with its own id, linked to the parent: the
parent stage's attempt waits on it, and the child's own terminal outcome ends that wait in
the same commit — a completed child completes the stage with `{"child_execution_id": ..,
"outputs": {<child stage>: <output>}, "child_invocation_summary": {"token_usage":
{"cost_micro_usd": ..}, "metering": {..}}}`, so a later stage reads `{{
stages.<sub>.outputs.<child stage>.parsed.<field> }}`; a failed or timed-out child fails it,
a cancelled child cancels it — so a child you cancel on its own ends its parent with a
recorded outcome of `cancelled` too.
The child's cost is charged to the parent's `cost_budget` and cost bound when the stage
terminates — completed OR ended by failure, timeout or cancel — not while the child runs: the
charge is every call the child billed, so it equals the child's own running cost (a stage
that structured-output validation retried billed each attempt, and only its last accepted
output appears under `outputs`, so a completed child's summary can exceed what `outputs`
shows), the summary names any child stage kata could not meter, and a `cost_bound` or
`cost_budget("halt", ..)` halts the parent on one rather than summing only the known share.
A cancel of the PARENT ends its waiting stage before the child ends: the parent's own
terminal settles the stage `cancelled`, charged what the child had billed by then. That is a
LOWER BOUND — a stage the child started before its cancel landed may still finish and bill,
and that spend lands on the child's own record only (the node-wide spend counts every call
once, at the child).
Shell stages carry no token cost, so a child of shell stages charges 0. A stage that itself
FAILED is charged the same way — the usage the worker reported for its billable call, an authoritative
`0` when the stage provably made none (a shell stage, or a failure before any call), and
`unavailable` when a billable call happened but its cost cannot be measured. Every failed,
cancelled or orphaned attempt that was DISPATCHED records that charge on its terminal: an agent
turn the main refused after it ran (a `/work` delta out of scope, an exit or capture its
stage fails, a result adoption refused) is charged the usage its turn reported; one the main
lost sight of (its worker died, it overran its wall or start deadline, the main restarted),
or one its worker refused at or after its container without a usage report (a turn whose
answer is unknown, a harness that died mid-turn), is `unavailable` naming its adapter and
declared model, because the turn may have been issued; a shell capsule, and a frame that
provably never reached a worker, is the authoritative `0`. So
under a hard cost policy (a `cost_bound`, a `cost_budget("halt", ..)`) an agent attempt the
main lost sight of halts the run `metering_unavailable` — also where its stage's own failure
would be tolerated, as an advisory topology child's is (such an attempt is PROVEN AMBIGUOUS
and never retried either way). The operational database refuses a dispatched attempt's
failure terminal that states no charge, or an empty one (`terminal_charge_required`), and
every cost reader — the run's own halt check, a loop's bounds, the record's
`running_cost_micro_usd` and `metering`, a parent's child summary — reads a dispatched
attempt's terminal that carries none as unknown, never as `0`.

**Walk-away bounds.** kata applies no spend limit unless one is authored:
`workflow(bounds = [..])` and `loop(bounds = [..])` take a `time_bound(ms)`, a
`cost_bound(usd)` and a `token_bound(n)`, each opt-in. `time_bound` is the portable
walk-away — kata reads the clock itself, so it holds over every adapter and credential —
and with each stage's own wall (see "Stage wall-time bounds") it is the bound to author in
a pack meant to run on any node. The std packs kata ships author `time_bound`s alone:
no `cost_bound`, no `token_bound` and no `cost_budget` of either mode. A workflow
`time_bound` is measured from the run's first dispatch at each stage terminal, at the
instant kata recorded it: a run resumed after its bound passed measures the stages it
already ran as the live run did, and walks away at its next terminal. A `cost_bound` or
`token_bound` holds only where kata can measure what it caps, so CHECK refuses a
`cost_bound` over an agent stage whose adapter kata cannot price
(`cost_bound_unenforceable_unpriced_adapter`, among the `kata workflows check`
refusals above) rather than letting the run spend past
a limit nothing measures; both nanocode kinds report every token class, so a
`token_bound` holds over either.

**Token bounds.** `token_bound(n)` — in `workflow(bounds = [..])` or `loop(bounds = [..])`,
opt-in like every bound — caps the tokens the scope's stages RECORDED: every class kata
records, `input + output + cache_read + cache_write`, which the adapters keep disjoint, so
the sum is the provider's own total (reasoning counts as output; a turn's prompt-cache reads
and writes are split out of the input the provider states, each counted once). It folds
exactly where the cost does —
each billed completion, each failed, cancelled or orphaned terminal's charge, and an
invoked child's summary (`child_invocation_summary.metering.tokens`) — and trips at
stage-terminal granularity when the total EXCEEDS `n`: the tripping stage keeps its outcome,
`<stage>#bound-halt-tokens` is recorded failed (`bound_exceeded: workflow tokens bound
reached …`), downstream stages are skipped, and stages already running finish on their own
and release nothing, exactly as a `cost_bound` trip. A stage whose token count is unknown (a turn that reported
none, a lost one) halts the run closed (`token_metering_unavailable`, a `#metering-halt`
row) — a subscription or unpriced turn whose tokens ARE known does not: a token bound holds
where a dollar bound cannot. A loop's token bound stops the loop the same way and routes
its `on_exhaustion`. A loop's bounds are charged, as each member is accepted, with EVERY
record that member's attempts made — its accepted completion, a structured-output retry's
rejected completion, a failed, cancelled or orphaned attempt's charge (an advisory topology
child's included), and a member topology's every root and child attempt; a loop
`cost_bound` trips closed on a record of unknown cost (`loop cost bound unenforceable: …
(metering_unavailable)`) and a loop `token_bound` on an unknown count, exactly as the
workflow scope does. The record states the known total as
`metering.tokens` and the uncounted stages as `metering.tokens_unknown`. A WORKFLOW-scope
bound charges every billed frame once, at its own fold — a stage's completion and a
structured-output retry's rejected one, a `loop(..)` member's every completion, a
`topology(..)` root's and each child's (a child charged under its topology stage, whose
`cost_budget` covers it and whose dependents its trip skips), and every failure terminal's
charge; a settled topology's fan-in, which restates its children's cost, is not charged
again. A run walks away ONCE, whatever stopped it — a workflow bound, a halting
`cost_budget`, a metering halt: its first trip records the one walk-away row, and no later
trip records another (a bound the total still exceeds, a workflow budget re-crossed, a
metering halt after a bound's), on the live run and on a resumed one. From that row on,
every stage that terminates releases nothing: a stage already running finishes and keeps
its outcome, but its dependents are skipped, as are those of a `topology(..)` that settles
and of a `loop(..)` that resolves afterwards, whatever its record — a verdict, a bound,
`max_iterations`, an abort. And from that row on no stage starts: a stage the run would
dispatch next — one a completion before the trip released, one `max_concurrency` held
back — is skipped with every stage behind it, whatever it runs (a capsule, a join, a
`sleep()`, a child invocation, a workspace effect), and a plain stage's queued retry — a
structured-output retry, an agent fallback panel's next member — is never dispatched: the
stage fails, naming the walk-away row and its last attempt's failure. The one exception is
a capsule attempt a main that died left claimed and never dispatched — a plain stage's, a
retry's, a `loop(..)` or `topology(..)` member's: the restarted run's boot dispatches it
whether or not the walk-away row is on the chain, as the main that claimed it would have
(its stage runs, and releases nothing when it terminates). A `loop(..)` or
`topology(..)` stage released after the row is still claimed, and stops at its first
dispatch point as a pending one does. A run that walks away while a loop is pending stops the loop
at its next member: it dispatches nothing more and resolves `Exhausted` under its own
`on_exhaustion`, the exhaustion naming the walk-away row. Whatever that `on_exhaustion`
adopts, nothing behind the loop runs: the dependents of its gate and of every member are
skipped and no route on the gate takes an arm (under `escalate` the loop still parks, and
an approve adopts the worker's last output but releases nothing). A pending `topology(..)`
stage — static or a dynamic fan-out — stops the same way at its next dispatch point (its
root, or its declared or requested children): it dispatches nothing more, waits for the
members it already started, and fails naming the walk-away row, since a topology settles
only once every member ran; its dependents are skipped, and a topology that is a loop's
member fails as that member's death, which aborts the loop (a root parked on its
`approval` gate still waits for the operator, and an approve runs it — the root was minted
before the walk-away, so the operator's word starts it — before the topology stops at its
children). There is no
per-stage token bound, as there is no per-stage `cost_bound`; the 1 h default stage wall
timeout stays whether or not a bound is authored. No cost policy
at all, and `cost_budget("warn", ..)`, never halt the run on metering or spend: everything
is recorded best-effort — `running_cost_micro_usd`, `metering.unmetered`, the per-stage
charge — and the run continues. A child left `admitting` by a crash resumes at the next start, and the parent's stage
keeps waiting on that same child — a restart never starts a second one.
`workflows/smoke/subworkflow-parent-smoke.star` (with `subworkflow-child-smoke.star`) exercises
it.

**`memory_snapshot()`.** A `memory_snapshot(id = "..", kind = "task", status = "active")`
stage is the authored `kata memory snapshot` read as a workflow node: the main reads the node's memory store once — no process, worker,
capsule, sandbox or loopback API — and records the serialized envelope
`{schema_version, generated_at_ms, revision_head, object_count, objects}` as the
stage's accepted output, so a downstream stage reads
`{{ stages.<id>.parsed.objects }}` exactly as it would any stage output. `kind`
and `status` are optional closed-set filters — an unknown value is a load-time
error naming the accepted set, and the filters fold the stage's identity like any
authored field. A node with no memory store configured resolves the stage to a
recorded `memory_snapshot_store_unavailable` failure. An accepted snapshot
converges on its recorded resolution — a restart never re-reads the store — while a
failed one is retried when the stage is next presented, as a further attempt.
`workflows/smoke/memory-context-smoke.star` exercises it.

### Approval gates on `oci`

A shell stage with `approval = True` is parked, not run, until an operator decides. Its
capsule is built, published and declared, and its attempt waits in `awaiting_approval`
bound to that one capsule. No container runs, no worker is chosen, and no attempt
directory or cgroup exists before the decision.

`kata approvals` (and `GET /api/v1/approvals`) lists the gate with what approving it runs,
under `capsule`: the capsule id, its `argv` (the rendered command), the `/work` tree
artifact id and the Nix environment id. The capsule id covers all of them, and the
attempt cannot be rebound to another capsule. So the approval is for exactly what was
listed.

Beside it, every gate shows what its run was asked to do, read off the stored
invocation: `target`, the target the run's admission froze (an isolated run's fork base,
the branch a landing would move — none for a `pr:` target — and a `pr:` target's pull
request number, url, refs, title and body; absent for a run that forks no workspace), and
`params`, each param the workflow declares and does not mark `secret = True`, with its
admitted value (a default included). A secret param is never listed, neither its name
nor its value.

- `kata run approve <execution-id> <assignment-id>` records the decision and dispatches
  the capsule once, in one database transaction, to a worker chosen at that moment.
- `kata run reject <execution-id> <assignment-id> "<reason>"` records the decision and
  fails the stage `rejected: <reason>`, PROVEN NOT PERFORMED.
- A late decision depends on whether the run is still running. While its lifecycle is
  `running`, a second approve succeeds and dispatches nothing, and the opposite verdict —
  approving a rejected gate, or rejecting an approved one — is refused
  `approval_already_decided` (HTTP 409, op code `conflict`). Once the lifecycle is no
  longer `running` — a reject that failed the run, or a run that completed — every approve
  or reject is refused instead, with `… cannot dispatch after workflow
  terminalization` (HTTP 412, op code `conflict`, CLI exit 4). Neither answer changes
  anything.
- One approval authorizes one dispatch. If the main dies after the approval and before
  the frame reaches the worker, the next main settles that attempt PROVEN AMBIGUOUS and
  does not send it again. The stage fails, and nothing runs it again on its own: kata
  does not re-present a settled gate's stage.
- The decision records who made it, as the API transport proved it: with signed-token
  auth, `{"kind": "token", "issued_for": "<the token's label>"}`; on a loopback listener
  with auth disabled, `{"kind": "unauthenticated_loopback"}`. kata records no name it
  cannot prove.
- The approval binds the capsule that was SHOWN. Anything that arrives after the stage
  parked — an external input, steering, an answered human request — is not folded into
  it: the gate dispatches the parked bytes verbatim. To run the stage over newer input,
  reject the gate and re-run the pack. (Re-rendering a parked stage at approval would
  approve one thing and run another.)
- A gate does not expire. While it waits it holds its environment, so
  `kata node environment release` is refused `environment_bound_to_live_attempt`. Cancel
  the execution (`kata run cancel`), which settles the gate `cancelled`, PROVEN NOT
  PERFORMED, or reject the gate. A main restart leaves a waiting gate parked and listed.
  A gate whose execution has already ended is settled on the next sweep, with a reason
  naming the approval park; if the execution was cancelled, the gate is recorded
  `cancelled`.

### Blocking human requests on `oci`

A `human_request(.., blocking = True, stage = "<stage>")` holds its stage until it is
answered. Under `oci` the request is its own durable wait, run by the main (no container),
and the stage's container starts only after it is resolved — so the stage's command, and
the capsule identity, carry the answer. Render it with
`{{ human_requests.by_id.<id>.effective_answer }}` and who gave it with
`{{ human_requests.by_id.<id>.answer_source }}` (`operator` or `timeout_default`).

- The wait sends nothing, so `kata watch` shows the stage only as pending. Find it with
  `kata steer human-requests --execution-id <execution-id>` (or `kata run show`): the row
  reads `request_status: "awaiting_input"`, and its projection names when the default
  applies if the request has a `timeout_ms`.
- `kata steer answer-human-request <execution-id> <request-id> "<answer>"` resolves the
  wait once, recording the answer, `source: "operator"` and who answered as the API
  transport proved it (the same principal an approval records). The row then reads
  `answered`. An answer given before the stage is ready is accepted then, and the stage
  runs with it when its turn comes; its timeout never starts.
- A second answer, or one after the timeout's default was accepted, is refused
  `input_request_already_resolved` (HTTP 409) and names the answer that won. An answer to a
  request whose execution has already ended is refused `main_resolution_execution_terminal`
  (HTTP 409), and one whose execution has fixed its outcome but not yet ended — a cancel is
  closing it out — is refused `input_answer_after_terminal_intent` (HTTP 409); neither is
  recorded.
- Only a blocking request refuses an answer after its execution ends. An answer to a
  non-blocking (advisory) request, and an external input appended with `kata steer
  append-external-input`, are still accepted on an execution that has ended: the answer
  is recorded and its row reads `answered`, the input is answered `appended` and listed
  by `kata steer external-inputs`, and neither reaches a stage, since none runs again.
- With `timeout_ms`, the deadline sweep resolves an unanswered wait with the request's
  `default_assumption` (`source: "timeout_default"`) up to one heartbeat interval after the
  deadline, which is anchored at the moment the wait was claimed and survives a restart.
  The default is applied while the execution's runner is running; an execution whose
  runner has stopped gets it after the runner next starts (a main start builds a runner
  for every running execution before its deadline sweep).
- The answer is not written as execution evidence: the wait's accepted
  outcome is the only record, and every surface reads it.
- A main restart leaves the wait waiting and the stage held. `kata run cancel` ends it and
  the stage never runs (see "Cancelling a run").
- A stage that also declares `approval = True` waits for its request first, then parks at
  its approval gate with the answer already in the listed capsule.

`workflows/examples/durable-wait-signal.star` (answered) and
`workflows/examples/durable-wait-timeout.star` (left to its three-second default) exercise it.

### The determinism boundary

kata's execution model rests on one rule: orchestration is pure, and every
non-determinism and side effect is a named, idempotency-keyed effect whose result is
recorded, so replay returns it. A refusal that ends in "(determinism boundary, clause N)"
names one of its five clauses; the numbers are stable.

1. **Orchestration is pure.** Routing reads only recorded stage verdicts and outputs,
   never the wall clock, randomness or host state. Every edge condition an author can
   write routes on a recorded verdict, so no authorable edge routes on anything else;
   the verifier's `clause1_orchestration_impurity` check is a backstop.
2. **Side effects are idempotency-keyed effects.** A stage is one coarse effect; a VCS
   mutation runs in the main as a workspace effect, outside any capsule, and one whose
   outcome a crash left uncertain is reconciled from the repository, never re-issued
   blind.
3. **Replay returns recorded results.** A committed stage result always replays; a
   recovered run does not run an accepted stage again.
4. **Determinism classification picks the identity strategy.** Cache eligibility is
   derived from the checked stage, never authored: only a deterministic, hermetic
   (offline-sandbox) stage may declare `content_cache`, and a `model_reuse` hit must
   reproduce everything the stage did: an agent capsule's hit adopts the recorded
   `/work` delta, and a stage whose workspace writes or effects a replay of its recorded
   output would skip is refused.
5. **The contract is the membrane.** A stage's output is checked against its declared
   `outputs`; a mismatch is retried with the validation error as feedback, up to
   `validate_retries` times.

### The capsule content cache

A shell stage that declares `cache_policy = "content_cache"` is not run again when an
earlier run on this node already produced an accepted result for exactly the same work.
The second run's stage completes without a container: no worker is chosen, no attempt
directory or cgroup is created, and nothing is dispatched. Its `/out` result is the
earlier run's, byte for byte, and `kata run show` reports the earlier run's output with
`reused_from: {occurrence, execution}` added.

- **Authored only.** Only a stage that declares `cache_policy = "content_cache"` is ever
  reused. A stage that declares nothing is not, even when kata classifies it as
  cacheable: unauthored reuse waits until kata can re-run a stage to check that it
  really is repeatable. An approval
  gate is never reused, and `KATA_RERUN_REPEATABILITY=1` turns reuse off, logging one
  warning per execution.
- **The key is every input the container sees.** It covers the prepared action, the Nix
  environment, the platform, every mapping (so the exact `/work` bytes the stage reads),
  the rendered command and every budget. It does not cover the run: two runs of one pack
  over an unchanged workspace share a key. Changing one byte of the workspace, the
  command, the environment, a budget, or the kata build's contract version is a miss.
  No fence for ambient toolchains or host git history is needed: a
  capsule's toolchain is the node's declared Nix closure, which is in the key, and a
  capsule cannot read host git history — a stage that carries the run's git view (an
  agent stage, or one whose profile `requires` `git`) reads it from a content-addressed
  history artifact that is part of the capsule, hence of the key.
- **The key also covers kata's own fence.** It carries the node's executor term: the
  seccomp rules kata renders into every container, the content hash of the pinned
  youki, the OCI `config.json` kata renders for three fixed reference stages — a
  command, an agent turn with egress, a git view and a credential, and a nanocode turn
  whose init is `kata-toolhost` — the tool host's protocol and source, and the
  embedded harness: its nanocode rev, the Code Mode engine as kata runs it (the
  vendored engine, kata's patch and the source of the interpreter process a cell runs
  in) and that interpreter's syscall filter, its Code Mode limits, and the tool
  definitions and instructions it gives the model. A kata upgrade that changes any of
  them misses every earlier result, however old; an upgrade that changes none of them
  keeps them, because the term is derived from those bytes and never from kata's
  version. The term does not see what is not in those bytes: the provider entry
  (`kata-provider-youki`, `kata-oci-hook`), which the node's provider declaration names
  by content address; which credential file each agent adapter is given; a render path
  that only a value no reference uses would take; and the versions of the registry
  dependencies of nanocode, of its Code Mode engine, and of kata's interpreter host and
  tool host. The key carries the main's term, and every `kata-worker` — the supervised
  node too — states its own term when it connects; a worker that does not state one is
  refused. A worker built from a different kata, whose term differs, still takes work,
  but its results are never reused: the main records no hint for them and never adopts
  one, even through an older hint. Run workers from the same build as the main to keep their results
  reusable. The supervised node is no exception: the main starts `kata-worker` from
  beside its own executable at every node start, and only the main's own binary is
  pinned by an installed unit, so after rebuilding in place restart the main too.
  Hints keyed under an earlier term are never looked up again and are not
  reclaimed; they are small rows in a rebuildable file.
- **Every hit is re-checked.** The node keeps a hint (in `stage_cache.db`, table
  `capsule_reuse_v1`) that names which accepted run produced each key. Before adopting,
  the main verifies the earlier result the same way it verifies a fresh one: its bounds,
  its privacy, its manifest, and that every member is still in the content store. It
  also checks that the earlier run is still accepted and that its result is still
  declared. A
  failed check is a miss: the stage runs, and a stale hint is dropped. The hint holds
  no content and keeps nothing alive. Deleting `stage_cache.db` is safe; every stage
  just runs once more.
- **Retention.** The reusing run holds its own reference to the result. Nothing
  reclaims the result's bytes: kata has no content-store collection, so the store only
  grows.
- **Privacy.** A result is only adopted by a run that already holds identical input
  bytes, on the same node, under the one operator the node serves. So reuse reveals
  nothing that re-running the stage would not.

### Review loops on `oci`

A `loop(body = …, gate = …, max_iterations = …, on_exhaustion = …)` runs the authored
body-and-gate cycle durably: the loop itself is a main-resolved attempt (no container)
at `#op/<path>`, and each iteration's members — the body stages and the gate — run as
ordinary capsules. Each member's `/work` writes apply through the same `#apply/<stage>`
door any capsule stage uses, so an iteration's markers are the next iteration's inputs.
The gate's verdicts drive the loop exactly as authored: a `refine` verdict starts the
next iteration, an `approve` verdict ends the run approved at that iteration, a `block`
verdict fails it with the gate's feedback — and, with no `route()` or `branch()` on the
gate to route the block, skips every stage that depends on the gate, as `fail` below does
— and a spent `max_iterations` resolves under
`on_exhaustion` — `fail` fails the run and skips every stage that depends on the gate (as
a walk-away skips a tripping stage's dependents), `accept` adopts the last iteration's
outcomes, and
`escalate` parks the loop on the shared approval door: `kata approvals` lists the gate
and `kata run approve` / `kata run reject` decides it, write-once, exactly like a stage
gate. Under `accept` a `route()` or `branch()` on the gate routes the gate's last
classified report, so an implement → test loop whose test never passed reaches the
route's `failed` arm (say, a `park`). A gate whose `review_quorum` was not met on that
last verdict was classified `refine` whatever its root reported: a route on the loop's
verdict field reads `refine` and takes that arm, and a route on any other field of the
report skips every arm, so a candidate the quorum refused never takes the arm its root
alone would pick. The rewrite is the route's alone: the route's `Select` record names
the verdict `refine`, while the gate's own output — the run's `outputs`,
`{{ stages.<gate> }}` and `kata run show` — still reads its root's report (its
`approve`). Such a gate's verdict field must therefore carry the `refine` tag when
a route reads it: `kata workflows check` refuses a review-quorum gate of an
`on_exhaustion = "accept"` loop whose route on the verdict field has no `refine` arm
(`loop_accept_quorum_route_needs_refine_tag`). When a loop
`bounds=` limit trips before the last iteration's gate reported, no report judged the
candidate the loop ended on: the previous iteration's report judged an earlier tree (that
iteration's members, and any `/work` edit they made, were accepted before the trip), and a
trip in the first iteration leaves no report at all. Routing an earlier report would let an
arm act on a tree no gate judged, so nothing is routed, and when the run completes
its closeout parks that candidate at `parked/<exec-id>` (an isolated run in which no
stage downstream of the loop minted an attempt — the run ends on that candidate), so it is
never left as a completed run's workspace for `kata run promote`. Then, and under
`fail` and `escalate`, every arm of a route on the gate is skipped. A restart
re-derives the loop
from durable occurrences — finished iterations never re-run — and a recorded decision
that disagrees with the recompute refuses `expansion_decision_diverged`.

`kata run show` folds a loop onto its AUTHORED stage names under `oci`: each stage is
listed once, carrying its RESOLVING iteration's output — the approved iteration's on an
admitted loop, the last completed iteration's under `on_exhaustion = "accept"`. A downstream
stage's `{{ stages.<member> }}` reads the same resolving envelope `run show` lists, so
the run's outputs and the show read never disagree. The per-iteration record lives
in the member occurrences, not in output-key spellings. Under `on_exhaustion = "escalate"`
`kata approvals` lists the loop's gate on the shared approval door with the bound
detail under `expansion`.
`workflows/smoke/multistage-loop-smoke.star` exercises a two-stage body refining twice
and approving on the third iteration.
### The capsule model-reuse cache

An agent stage that declares `cache_policy = "model_reuse"` is not run again when an
earlier run on this node already produced an accepted result for exactly the same
turn. The second run's stage completes with no provider call: no worker is chosen, no
attempt directory or cgroup is created, and nothing is dispatched. Its stage output is
the earlier turn's response, byte for byte — plus whatever the earlier turn left under
`/work`, adopted as the recorded delta — and `kata run show` reports it with
`reused_from: {occurrence, execution}` added and an authoritative zero spend: the
model call was billed to the earlier run once, and the hit does not spend it again.

- **Authored only, agent only.** Only a stage that declares
  `cache_policy = "model_reuse"` is ever reused, and only when the stage is a real
  agent — a `shell` or `workspace_effect` stage makes no model request, so declaring
  the regime on one is refused at `kata workflows check` under `oci` rather than
  silently ignored. An approval gate is never reused, and `KATA_RERUN_REPEATABILITY=1`
  turns reuse off, logging one warning per execution.
- **The key is the whole turn.** Beside every input the content cache's key covers
  (the `/work` bytes, the environment, the platform, the budgets, kata's executor
  term), an agent capsule's key folds the rendered prompt, the adapter, the model and
  the credential reference — so a different prompt, model or `/work` tree is a miss,
  and the stage runs its own turn. Because the executor term is in the key, a kata
  upgrade that moves it pays for every reused agent turn once more, on its next run.
- **Reuse is capsule-scoped, not workflow-scoped.** The key carries no pack or
  workflow identity: two DIFFERENT packs that assemble equal agent capsules — same
  prompt, model, environment, workspace bytes — share a hit. A shared verdict stage
  authored in two packs reuses whichever execution accepted the equal capsule first.
- **A mutating stage reuses honestly.** The hit adopts the earlier turn's recorded
  `/work` delta, so an agent stage over `workspace = "rw"` may declare `model_reuse` —
  a fresh run that hits lands the same writes the recorded run made.
- **Bounded in time.** A hit is memoised spend, and half of what an agent turn does is
  the provider's — model updates and endpoints no key can capture — so the regime is
  bounded by age. A turn accepted longer ago than `[runtime]
  model_reuse_max_age_secs` is not reused: the stage runs its own turn, which becomes
  the source the next equal stage reuses. The value is a number of seconds; `0` or an
  absent key takes the 7-day default, and the string `"unbounded"` lifts the bound —
  any other value refuses the config at load. The age is counted from when the
  earlier turn was accepted, so reusing it again never extends it. Nothing is deleted,
  and the bound applies to `model_reuse` alone: a `content_cache` result of any age is
  still reused. The skip is logged at `info` as a reuse miss tagged
  `source_older_than_model_reuse_bound`. The bound is read at boot only: a reload that
  changes it is reported as restart-required.
- Every hit is re-checked and held by the reusing run's own reference — the same
  verification rules as the capsule content cache above.

### The `oci` repository census

A `worktree_isolated` pack asks kata to materialize the repository into a per-execution
workspace. Under `oci` that workspace is produced by the jj backend — the sole
VCS effect backend — and a capsule maps the committed tree bytes VERBATIM: nothing runs
git's checkout-side machinery. So before the first stage is dispatched, the submit runs a
read-only CENSUS of the workspace's base tree and git store and refuses the run at
admission, `oci_unsupported_repository_features`, when the repository carries a feature
whose git semantics jj cannot reproduce or whose object store is incomplete by design:

- a committed `.gitmodules` or any submodule gitlink in the base tree;
- a declaration that makes git write different bytes than the committed blob on this
  platform — `filter` set (the clean/smudge hook Git LFS rides), `ident` set (`$Id$`
  expansion), `working-tree-encoding` set, or `eol=crlf` — in any committed
  `.gitattributes` at any depth or in `$GIT_DIR/info/attributes`, including through an
  `[attr]` macro a rule sets, plus `core.autocrlf=true` or `core.eol=crlf` in the
  repository's own config, and a non-empty `core.attributesFile` pointing declarations
  at a file the census cannot read. Declarations that do not convert — `text`,
  `text=auto`, `-text`, `binary`, `eol=lf`/`native`, `diff`, `merge`, `export-*`,
  `linguist-*`, `-filter`/`!filter` — are admitted, as are an unused `[filter "name"]`
  config section and the mere presence of an attribute file;
- a `$GIT_DIR/shallow` boundary (a shallow clone);
- `extensions.partialclone`, `remote.<name>.promisor` or
  `remote.<name>.partialclonefilter` in the repository's config (a partial clone).

The refusal names EVERY finding, so one pass lists the whole refused set. The submit is
accepted as a run and ends `failed` with reason `submit_setup_failed` — naming the census
refusal — before any stage is dispatched and before any token can be spent; the workspace
it materialized is removed as part of the same closeout. A run crashed between workspace
creation and the census is asked the same question at the next start's recovery, before it
is authorized `Running`, and ends the same way. The census reads only the committed tree
and the repository's own `.git` (`config`, `info/attributes`, `shallow`, resolving
`gitdir:` indirection and linked-worktree `commondir`) plus the repo-local `include.path`
files git itself honors — never a global or conditional (`includeIf`, `~`) include, and
never the tree's checkout.

jj is the one execution-workspace backend and the one VCS effect backend; `[vcs] jj_repo`
names the repository the jj provider adopts.

There is no other engine to fall back to: a repository carrying a refused feature cannot
run a `worktree_isolated` pack in this build. The census runs only for `worktree_isolated`
packs; a non-isolated pack creates no workspace and is never censused.

Census cost is on the admission path: one walk of the base tree plus a read of the small
`.git` files above, timed as `kata_vcs_operation_duration_seconds{operation="census"}` the
same as every other jj operation. Measured on a repository of 9,376 tracked files, 341 MiB of pack, carrying both `.gitmodules` and a real
submodule gitlink — so the full aggregation path ran): ~190 ms cold (first call, including
workspace and repo load) and ~25 ms warm. It is not a git subprocess and never touches the
network.

### The committed base tree at `/work` (`oci` + `worktree_isolated`)

Immediately after the census admits the repository, admission converts the workspace's
COMMITTED base tree — the tree of the commit the workspace was created over — into a tree
manifest, streams every member into the node's content store, and records one durable
`execution_work_tree_heads` row naming the base commit and the manifest's artifact. That
row is the execution's `/work` head: every capsule stage maps exactly that artifact, so a
stage sees the committed base bytes verbatim — regular files, executables and symlinks
carried — and an edit sitting uncommitted in your checkout is structurally never an input.
There is no per-stage scratch-directory walk on the isolated arm — and, since the
durable-head model landed, none on the non-isolated arm either.

The conversion refuses admission rather than carry a tree `/work` cannot reproduce:

- `work_tree_base_conflicted` — a path still conflicted in the base commit;
- `work_tree_base_gitlink` — a committed submodule gitlink (the census already refuses
  this set; the conversion refuses it again on its own authority);
- `work_tree_base_unrepresentable` — a path or symlink target the manifest cannot carry,
  or a workspace whose base is not a single commit;
- `work_tree_base_member_too_large` — one member over the 64 MiB per-member bound the
  worker's materializer enforces;
- `work_tree_base_bound_exceeded` — the tree over the node's configured INPUT ceiling:
  `[node] work_tree_max_bytes` (default 1 GiB) for total member bytes, and
  `[node] work_tree_max_entries` (default 100 000) for manifest entries. These are the
  input bound only; capsule RESULT budgets (`result_bytes`/`result_entries`) are a
  separate class and do not read them.

The publication is durable before `Running`: a crash after the tree is published but
before the head row lands leaves retained content no execution names, and the next start's
recovery re-runs the publish — content-addressed, so it dedups — and records the head. A
re-drive that derives a different tree or a different base commit for an execution that
already has a head is refused `work_tree_head_divergent`, and an isolated execution that
reaches dispatch with no recorded head is refused `work_tree_head_unrecorded` rather than
falling back to a walk. The conversion is timed as
`kata_vcs_operation_duration_seconds{operation="base_tree"}`. Publication cost, measured
the same way as the census on the largest local repository's real content (9,116 file
members, 155 MiB): ~7.8 s cold and ~7.0 s on a re-drive that deduplicates every member —
seconds of admission wall time on a development build, visible through the metric.

A NON-ISOLATED `oci` execution gets the same durable head, seeded once: admission
declares the canonical EMPTY tree as the root `execution_work_tree_heads` row with
EMPTY base and candidate commits — there is no workspace to walk and nothing
legitimately pre-populates one before admission, so no scratch directory is
materialized at all. The empty base/candidate commits are the recorded fact that
there is no jj checkout to rewrite, which is what routes that execution's `/work`
applies onto the CAS-only leg (below). The same re-drive runs when recovery finds
an `Admitting` execution with no head: the empty-tree seed converges. A capsule
whose `/work` mapping names anything but the recorded head — a previous stage's
`/out` included — is refused `work_tree_not_role_bound`, and an execution that
reaches dispatch with no recorded head is refused `work_tree_head_unrecorded` on
either arm.

### What a run works on: `--target`

A `worktree_isolated` workflow forks its `/work` from a TARGET, resolved once,
before the run is accepted, and frozen into the run's admission: `kata run <pack>
--target <spec>` (the same field is `target` on the REST `POST /api/v1/executions`
body and the MCP `run` tool). This build resolves two:

- `trunk`, the default when you name none — the configured `vcs.trunk`, else the
  remote's `HEAD`, else the sole local branch. The run records the commit it resolved
  to as its fork base, trunk's name as its landable branch, and the head's first
  parent as its review baseline.
- `pr:<N>` — the forge's pull request N, read with `gh pr view` from the repository
  root (so `gh` must be installed and authenticated on the main, and its default
  repository is the one it reads). kata fetches the pull request's head
  (`refs/pull/<N>/head`) and its base branch from the ONE git remote whose
  configured URL is the repository `gh repo view` names, straight into the run's pins
  — no tag, remote-tracking branch or `FETCH_HEAD` is written. The run forks the pull
  request's head, its review baseline is the base branch at the fetched commit (with
  their merge base), and it has no landable branch, so a workflow that promotes or
  exports is refused `target_not_landable` before the forge is asked anything; a
  read-only workflow (the `review` pack's shape) is admitted. The pull request's number, url, branch
  names, title and body are frozen with it; the title and body are cut to 512 B and
  8 KiB at a character boundary, and whether each was cut is frozen with it
  (`target.pr.title_truncated`, `target.pr.body_truncated`). Resolution — both
  forge reads and the fetch — is bounded by one 300 s deadline and holds no
  admission permit, so it never delays a shutdown. A closed or merged pull request
  is admitted like an open one: kata never asks the forge for its state, and a
  pull-request run lands nothing, so it reviews the head it pinned.

`kata run show <id>` prints the frozen `target` in the execution record.

Because the target is frozen, the run's base does not move with the branch: a
commit that lands on trunk after admission — even across a crash and restart of the
main before the run's workspace existed — is not part of the run. Uncommitted edits
in your checkout are not part of any run either (the base is a committed tree); `kata
run` prints one notice on stderr when the checkout you run it from has uncommitted
tracked changes (read with `git --no-optional-locks status`, so it never writes your
checkout's index or takes its lock). Until the run is terminal, git refs under
`refs/kata/targets/<execution-id>/` keep the frozen commits from being collected
even if trunk is force-moved; kata deletes them when the run's cleanup completes,
and boot deletes any left by a run that was refused or crashed before it was
accepted. A schedule's target is resolved at every fire, so "nightly on trunk" runs
that night's trunk.

Refused at submission, before anything is admitted or spent, by name:

- `target_spec_invalid` — a spelling that is not a target;
- `target_kind_unsupported` — a target kind this build does not resolve
  (`branch:`, `commit:`);
- `target_requires_isolated_workspace` — a target on a workflow that forks no
  isolated workspace;
- `target_children_unsupported` — a non-trunk target on a workflow that can invoke
  an isolated child;
- `target_not_landable` — a workflow that promotes or exports its candidate (it
  holds a `promote` or a `forge_export` stage), under a target with no landable
  branch: a pull request (refused off the spelling, before the forge is read) or a
  repository with no commit yet;
- an unresolvable trunk (`target not resolved: …`) — the repository cannot say
  which branch is trunk; the refusal names the `vcs.trunk` remedy.
- `target_requires_git_backend` — a target with a commit to freeze, in a jj
  repository on jj's simple backend, which has no git object store to pin it in;
  run kata over a git-backed jj repository.
- for `pr:<N>`, in the order they are checked:
  - `target_forge_unavailable` — the node has no forge, `gh` is missing or not
    authenticated (`gh auth login`), it failed or did not answer within the bound
    (the forge's reads leaving none for the ref checks included), or it answered
    outside its `--json` contract or about another number;
  - `target_pr_not_found` — the forge says it has no pull request N;
  - `target_pr_ref_invalid` — the head commit is not a 40-hex id, or the base or
    head branch name is not one git accepts as a plain branch name (checked before
    any fetch: the head name is the author's and is never composed into a refspec
    or the fetch's argv);
  - `target_pr_url_invalid` — the url is not `https://<host>[:<port>]/<path>/pull/<N>`
    for this N, where `<path>` is two or more segments of ASCII letters, digits, `.`,
    `_` and `-` (the owner and repository, behind an optional path prefix), within
    2048 bytes;
  - `target_pr_remote_unresolved` — no git remote fetches from the repository the
    forge serves (add one, or name the forge repository with `gh repo set-default`),
    more than one does (remove all but one), or the one that does has a name starting
    with `-` (rename it);
  - `target_pr_fetch_failed` — the fetch failed or did not finish within the bound;
  - `target_pr_head_raced` — the pull request's head moved between the forge's answer
    and the fetch; submit again;
  - `target_pr_no_merge_base` — the head shares no history with its base.

  A refusal after the fetch deletes the refs it wrote.

Refused after acceptance, against the target the run froze, by name:

- `target_trunk_renamed` — at landing (a `promote` effect or `kata run promote`):
  the trunk the node resolves now is not the branch the run froze; nothing moves. An
  operator promote (the CLI, `POST /api/v1/executions/<id>/promote` or the `promote`
  operation; `kata mcp` serves no promote) answers it as a conflict: HTTP 409, op code
  `conflict`;
- `target_trunk_raced` — at landing: a writer outside kata moved the trunk in jj's
  view between the landing's read of it and its fast-forward (a `jj` command on the
  repository, or a `git` one that another run's start imported meanwhile); nothing
  moves. An operator promote answers it as a conflict (HTTP 409, op code
  `conflict`) and is safe to re-issue: the next promote judges the trunk as it is
  then. A `promote` effect fails its stage with it. A `git` move that nothing
  imported in that window is refused instead by the landing's export to git, also
  with nothing moved, as an internal error (HTTP 500);
- the structural refusals of a stored target at recovery (`target_presence_invalid`,
  `target_head_invalid`, `target_compare_invalid`, `target_fields_inconsistent`,
  `target_pr_url_invalid`, `target_pr_text_over_bound`), and `target_head_absent` at workspace creation when
  the store no longer holds the frozen head;
- `work_tree_base_not_the_target` — at workspace publication, a workspace left
  standing on another commit is not this run's input.

A schedule fire whose target is refused is recorded as that occurrence's firing,
with the refusal and no execution, and the schedule's cursor moves past it: the
occurrence is not retried, and the next one fires on schedule.

#### Reading the target in a template: `target.*`

Every `prompt=` and `run=` template of an isolated workflow reads the frozen target:

| Read | Renders |
|---|---|
| `target.spec`, `target.kind` | the spelling asked for (`trunk` or `pr:<N>`), and `trunk` or `pr` |
| `target.head` | the frozen fork base, 40 hex digits (`none` for a repository with no commit) |
| `target.branch` | the landable branch — trunk's name (`none` for a PR) |
| `target.compare` | `.name`, `.commit`, `.merge_base` — the review baseline; a trunk target's is its head's first parent, with `name` `none`; `none` when the head has no parent |
| `target.pr` | `.number`, `.url`, `.title`, `.body`, `.base_ref`, `.head_ref` for a pull-request target; `none` otherwise. `.title` is at most 512 B and `.body` at most 8 KiB, cut at a character boundary; `.title_truncated` and `.body_truncated` say whether each was cut |
| `target.changed_files` | `[{path, kind}]` from `compare.merge_base` to `head` (`kind` is `added`, `modified` or `deleted`), at most 2,000 entries; `target.changed_files_truncated` says whether it was cut |
| `target.diff` | git's unified diff over the same range, at most 256 KiB, cut at a whole line; `target.diff_truncated` says whether it was cut |

Every key is always present, so a template reads `{% if target.pr %}` without a
strict-render failure. The values are the run's frozen facts, and the file list and the
diff are computed from the two frozen commits when a template first reads them, so a
re-render — a retry, a restart — renders the same text, unless the main was upgraded in
between to a jj-lib whose line diff splits the change into different hunks. The diff is
git's format with three lines of context. It writes a path exactly as `git diff` does
under the default `core.quotePath=true`: a path holding a control byte, `"`, `\` or a
non-ASCII byte is C-quoted (`"a/new\nline.txt"`), and a `---`/`+++` name holding a space
ends in a tab — so no path in a pull request can write a line git would not. A path
whose name is not UTF-8 is not written at all: jj-lib refuses to read a tree holding
one, so when a directory that differs between the two commits (the root does whenever
anything changed) holds such a name, `target.diff` and `target.changed_files` both
fail, and a template reading either fails its render. It writes a line that is not
UTF-8 lossily, and can split a change into hunks differently from git's default
algorithm.

A pull request's title, body and head branch, and the paths and contents of its change,
are text its author chose; its base branch, URL and the baseline's name come from the
forge; and a branch name — so `target.branch` and `target.spec` — may hold `$`, `;`, `&`
or a backtick. A prompt may read every key. Frame the third-party text as untrusted, and
render it through the `untrusted` filter: `{{ target.pr.body | untrusted }}` starts every
line of the value with `> `, writing each line boundary in it — LF, CRLF, CR, VT, FF, FS,
GS, RS, NEL, LS, PS — as a newline and `> `, so the author's text begins no line of the
prompt, and a frame's end line or a note written without `> ` is the pack's own.
`untrusted` refuses a `none` value at render. In a shell
`run=`, only `target.head`, `target.kind`, `target.compare.commit`,
`target.compare.merge_base`, `target.pr.number` and the four `_truncated` flags may be
written bare; every other read must end its output expression with `| shquote`, which
renders it as one single-quoted word, AND be written where the shell reads that quote as
one word — in the command text or inside `$( … )`:

```python
show = stage(id = "show", agent = "shell", run = """
git diff {{ target.compare.merge_base }} {{ target.head }} > /out/range.diff
{% if target.pr %}printf '%s\n' {{ target.pr.title | shquote }} > /out/title.txt{% endif %}
""")
```

`kata check` refuses, naming each read:

- `template_untrusted_in_run` — in a shell `run=`, a read of any other `target` key, the
  bare `target`, a subscript, or a key below one (`target.head.x`), anywhere but inside
  an output expression whose OUTERMOST operation is `| shquote` or an `{% if %}`/`{%
  elif %}` condition (or the condition of an inline `a if c else b`). An output that
  ends in another filter after `shquote`, a `{% set %}`, a `{% for %}` over a list, a
  macro argument or a `{% filter shquote %}` block are refused; every branch is checked,
  taken or not. A `| shquote` read is refused too where its quote is not one word: inside
  `"…"`, `'…'`, `$'…'`, a backtick, `${…}`, `$((…))`, a comment or a heredoc body
  (quoted delimiter or not), right after `\` or `$`, as a heredoc delimiter, in a
  macro, `{% set %}` or `{% filter %}` body, or where the lexer cannot follow the text
  (a `case` inside `$( … )`). The check lexes the template's literal text along every
  control path, taking each expression's value to open and close no quote. It does not
  see what a command does with the word: `sh -c {{ target.pr.title | shquote }}`, `eval`
  or `ssh` hand the title to a second shell, which runs it — do not.
- `target_unknown_in_template` — `target.<key>`, `target.compare.<key>` or
  `target.pr.<key>` the namespace does not answer.
- `target_requires_isolated_workspace` — any `target` read in a workflow that is not
  `worktree_isolated`, which freezes no target.

### The git view: `/work` is a real repository (`oci` + `worktree_isolated`)

An execution whose pack contains an agent stage — or a stage whose sandbox profile
`requires` the `git` program (`sandbox_profile(requires = ["git", ...])`) — gets a real
git repository at `/work` for exactly those stages — not the host's `.git` bound in, but a disposable one assembled from
content-store bytes. At admission the main packs every object reachable from
the committed base (and only those) into a git-history artifact alongside the
`/work` tree, records it on the execution's `execution_git_views` row, and the
agent capsule's worker materializes it as two mounts: `/git-history` READ-ONLY
and `/git`, a per-attempt writable scratch whose `objects/info/alternates`
reaches the history. `/work/.git` is a gitfile pointing at the scratch, so
inside the container `git status`, `log`, `diff` and `blame` answer against the
run's real committed history the moment the tree is up.

The repository is disposable by construction. The agent's commits land on the
scratch ref `refs/heads/kata/<execution-id>` — evidence the worker reads back
bounded (32 commits, subject/body truncated) into the attempt's
session-evidence blob as `SessionEvidence::scratch_commits` — and are NEVER
adopted: kata takes the stage's delta off the
working tree, and promotion is `WorkApply`, not `git merge`. The worker reads
that evidence on the host from bytes the agent could rewrite, so the read admits
only what `git commit` leaves: directories and regular files no more than 64
deep, loose objects, no `commondir`, a `HEAD`, `packed-refs` and each file under
`refs/` of at most 1 MiB, and a scratch ref that names a commit rather than
another ref. Of the objects, only the COMMITS the read walks are bounded — each
at most 16 MiB, both its loose file and the size it declares; the blobs and trees
those commits carry are never read, so a large file the agent committed does not
count against the bound. A scratch `/git` holding a symlink, FIFO, socket or
device, a pack (the agent ran `git gc` or `git repack`), a symbolic scratch ref
(`git symbolic-ref`), or anything else outside that set is evidence that could
not be collected, and the turn's attempt is refused naming what it found. The
read restores the scratch's `config` and alternates line to the ones kata wrote
before it opens the repository, so neither steers it, and it ignores
`refs/replace/`. A depth-limited history (`[git_view] history_depth`) reads as
git reads it: the walk stops at the history's own `shallow` boundary. There are no
remotes, so `push` fails by repository shape rather than by a filter kata
imposes. History objects the base cannot reach — anything on the host the
committed base does not name — are simply not in the artifact.

The view's base and its branch ref come off the run's FROZEN target (see "What a
run works on: `--target`"), never off a trunk resolved later: trunk's name sits at
the frozen head, so `git log main..` and `git diff main` answer the way they would
in your checkout even if the branch moved, was renamed or was deleted since
admission. The artifact also always carries the target's review range — the head
and its baseline (for a trunk target, the head's first parent) down to their merge
base — whatever `history_depth` says, so with `history_depth = 1` a trunk run's view
still holds two commits.

Admission refuses rather than boot a partial view: a base that is not a commit
the store holds (`git_view_base_commit_absent`), a workspace whose base is not the
head the run's target froze (`git_view_base_not_the_target`), a missing inherited
identity (`git_view_identity_unavailable`), or a history over the node's `[git_view]
history_bytes_ceiling` (default 1 GiB; `history_depth` caps commit count and
marks the view shallow) — named `git_view_review_range_over_ceiling` when the
review range added commits the depth-bounded walk did not, and
`git_view_history_over_ceiling` otherwise. The view's index refuses no file name
Linux admits but git's own spellings of `.git` — a tree naming `docs/a:b.md`, `?`,
`*`, a trailing dot or `CON` is viewed. A base tree naming `.GIT`, `git~1` or `.git`
with a code point HFS+ ignores (such as a zero-width joiner) fails the run
(`Internal`), and one naming `.git` fails earlier, at the workspace's checkout. A
repository with no commit gets no view:
its run's base is the empty root, which no git store holds, so admission refuses it
`git_view_base_commit_absent`; and a repository whose trunk cannot be resolved never
reaches admission (`target not resolved: …` at submission). Any other stage maps
`/work` bare, and a non-isolated
`oci` execution has no repository to root one at — on a non-isolated run
`requires = ["git"]` enforces the PROGRAM alone (the environment's `git` must be
on the capsule's `PATH`, or CHECK refuses `environment_requirement_unmet`) and
carries NO view: no `execution_git_views` row is recorded, and the capsule maps
`/work` without a repository behind it.

`requires` is also how a stage says which programs it needs: under `oci` a capsule's
tools are the node environment's (`[node] environment`, one per node), a per-stage
`toolchain`/`rootfs` pin is refused, and each program `requires` names must be on the
environment's `PATH` — checked when the pack is admitted on a booted node, and again
before every dispatch.

### `reads=` confinement under `oci`

`stage(reads = [...])` declares the paths a stage may read — repo-relative
globs against the execution worktree; the compiler already refuses a pattern
that can never name one (absolute, `..`, `~`, empty). There is no shared
filesystem to fence — the enforcement is at
MATERIALIZATION: the stage's capsule carries a work view minted from the
declaration, and the worker writes into the container's `/work` only the
committed-head members the view covers. A member outside the view is not in
`/work`: `cat` exits non-zero on it.

The view confines `/work` and nothing else. A stage that also carries the git
view (an agent stage, or a shell stage whose profile `requires = ["git"]`, on a
`worktree_isolated` execution — "The git view", above) gets `/git-history` and
`/git` unfiltered: the history packs hold every object reachable from the base,
and the copied `index` lists every tracked path, so `git show HEAD:<path>` and
`git ls-files` read members the view left out of `/work`. `reads=` is not a
secrecy boundary for such a stage; keep what it must not read out of the
committed head.

The mint is deliberate, not ambient: a confinable stage (the deterministic
class — a deterministic command, offline, a declared workspace) with a
non-empty `reads=` gets a view; anything else maps the whole head exactly as
before, and `reads = "whole-tree"` compiles to the empty closure — no view.
On a writable workspace the include list is the reads union the declared
`produces_files` (a write the container must reach cannot live outside the
view it materializes); on `workspace = "ro"` it is the reads only, and a
`produces_files` path that does not exist in the head gets its enclosing
directory created, never invented bytes. A symlink inside the view
materializes AS the symlink — verbatim, dangling if its target is outside —
never its target's bytes: the closure confines members, not link contents.

The view is contract data on the capsule — folded into the capsule id and so
into the reuse key, so two stages differing only in `reads=` are different
stages and a confined one can never adopt an unconfined capsule's result —
and a capsule minted with a view but no `/work` mapping is refused
`work_view_requires_work` rather than silently unconfined.

The delta is the other half of the view: a base member the view did not
cover is UNCHANGED, never a deletion. The worker knows the view hid it and
emits a delta over the members it materialized — a confined stage cannot
erase the rest of the head by hiding it. The produce-side fence
(`work_delta_out_of_scope`, below) still judges every delta member against
the declared write closure.

### The `/work` delta after a capsule stage (`oci`)

A capsule stage that maps `/work` ends its attempt with the worker walking the
materialized directory without following a symlink and publishing the
DIFFERENCE against the tree the stage started from — added, changed and
removed paths — as a content-addressed delta artifact, reported on the
completion frame beside `/out`. A stage that changed nothing reports an EMPTY
delta: the acceptance records a delta whenever `/work` was mapped, and an
absent delta means the stage had no `/work` mapping — the two are never
interchangeable. The delta, the member objects it names and the result tree
are verified and retained together when the stage's outcome is accepted, so a
run's `/work` mutation is a durable artifact, not a worker-local observation.

The walk carries regular files (mode included), deletions, and symlinks
VERBATIM — a created or retargeted link is a change, an unchanged one is not,
and a file↔link flip records the new kind. It refuses by name:

- `work_delta_special_file` — a fifo, socket or device under `/work`, which no
  tree can represent;
- `work_delta_unrepresentable` — a name or symlink target the tree types
  cannot carry;
- `work_delta_member_over_ceiling` — one file over the 64 MiB per-member
  bound;
- `work_delta_entries_exceeded` / `work_delta_bytes_exceeded` — the delta over
  the stage's own `work_delta_entries=` / `work_delta_bytes=` promise (default
  10 000 entries / 64 MiB, capped at `[node] work_delta_entries_ceiling`,
  100 000, and `[node] work_delta_bytes_ceiling`, 1 GiB). A refused delta
  publishes nothing and fails the stage.

A worker that dies after the delta is durable but before its completion frame
reaches the main leaves orphan bytes no reference names (they stay on disk:
kata has no CAS collection); the attempt is
reclaimed and the stage re-runs — a retry over an identical tree republishes
the identical object. A crash is not the only source: an attempt that ran and FAILED
leaves what it published durable in the content store — a command's captured stdout
and stderr and any `/work` delta; an agent turn that completed but whose result the
main refused, its `/work` delta, its response and its nanocode session evidence — and
its failed outcome names none of them (`outputs.<stage>` is `null`), so those objects
stay on disk with nothing referring to them either.

### The `/work` apply — one stage's write is the next stage's input

When the completed stage's delta is accepted, the MAIN applies it to the head the
stage's coordinate names. An ISOLATED execution's root head is played onto the
execution's jj working-copy commit as a `kata.effect`-tagged operation and the
head advances to the new candidate; a non-isolated root head and every
`parallel()` branch head carry no candidate commit, so their apply is CAS-only —
the applied tree is published and the head row compare-and-swapped, with no
repository write at all. Either way a later stage's `/work` materializes
with every earlier stage's writes. A stage that changed nothing resolves
without any repository write. A dependent stage is not dispatched until its
dependency's apply has committed, so a stage never reads a half-applied tree.
The apply refuses and fails the stage rather than run — by name:

- `work_delta_out_of_scope` — the delta writes a path outside the stage's
  declared `produces_files` closure. The WHOLE delta is refused, nothing is
  partially applied, and the attempt settles performed-but-failed. An empty
  `produces_files` means whole-tree scope.
- `work_delta_unsupported_repository` — the delta writes a `.gitattributes`
  carrying a checkout-conversion declaration (`filter`, `ident`,
  `working-tree-encoding`, `eol=crlf`), judged by the same census parser the
  `oci` admission runs — a conversion the container cannot have performed
  honestly is never applied.
- `work_delta_base_stale` — the delta's recorded base is no longer the `/work`
  head row it was claimed against; a delta built against a stale head is refused
  rather than rebased. `parallel()` branches do not hit this at the join — each
  branch's delta is computed off the barrier's frozen fork base and merged
  (above) — so the refusal is what a stage sees when its own head moved
  underneath it.
- `work_apply_candidate_diverged` — the execution workspace's checked-out
  candidate is not the commit the head recorded; the apply refuses rather than
  append to an unfamiliar tree.

The apply is a durable, idempotent effect: if the main dies between the
repository write and its durable acceptance, recovery classifies the
workspace (the `kata.effect` tag on the operation, then the candidate's own
predecessor chain) and records the outcome — the delta is never re-applied.

### Stage progress under `oci`

`progress_visibility` on a stage shapes what a running capsule reports while it
works:

- `progress_visibility = "off"` (the default) streams nothing;
- `progress_visibility = "summary"` sends each observation's kind — an agent
  session event's name, a shell stage's `stdout:`/`stderr:` — plus a short head
  of its text;
- `progress_visibility = "full"` adds the observation's bounded text.

On an agent stage the stream is the adapter's observed session events — tool
calls, message chunks, refusals — with every provider string passed through the
same secret-scrubbing the stage's evidence record uses. On a shell stage it is a
bounded tail of the container's stdout/stderr, line by line.

The scrub reads an agent's message chunks as one stream: if the model provider echoes
the stage's credential split across two or more chunks, the credential is still
replaced whole. A chunk's text is held back while its end could be the start of the
credential (never more than the credential's length less one byte), and sent with the
next chunk once that one shows it is not; a credential the stream never finishes is
never sent at all. Other session events — a tool call's name, a refusal's text — are
scrubbed one at a time. The stage's durable record is scrubbed separately: the final
response is scrubbed whole before it is stored.

The stream is deliberately bounded so a noisy stage cannot flood the node.
Streamed text — message chunks, stdout/stderr lines, an agent's streaming-delta
notifications — sends at most one frame per kind per 250 ms window: inside the
window a chunk replaces the pending one of its own kind (superseded ones are
compressed, not counted as dropped), and the latest is sent when its window
ends, so a stage that goes quiet mid-turn still shows the last thing it did. A
lifecycle event — a model call starting, completing or failing, a tool call or
result, a turn boundary, a refusal — is never compressed and never waits: it is
sent at once, after any chunk held before it, and starts a new window, so the
stream keeps the order things happened in. A chunk kind can therefore send more
often than every 250 ms when lifecycle events arrive faster — one frame per
window plus one per lifecycle event. Each frame carries at most 4 KiB of preview (80 bytes under `summary`), and
a stage's whole run carries at most 64 KiB of streamed preview plus, separately,
64 KiB of lifecycle events, each charged only for what is actually sent. What
the bounds refuse — a spent budget, or a burst faster than the worker can send —
is reported as `dropped` on the progress event, and when a stage's bounds
refused anything its last frame is a `dropped: <n> …` frame with the whole
count, sent after everything else and never itself refused, so a burst refused
just before the stage ends is still reported. A truncated stream announces
itself rather than reading as complete: while `dropped` stays 0 and no SSE
`progress_lagged` frame arrives, every lifecycle event the stage's agent
reported up to the last frame you received is on the stream.

Progress frames reach the operator through `kata run show`'s progress, the API, and the SSE `progress` event (whose
`dropped` field reports the count above). The stream is observability, not
durability: it is never written to the ledger, it does not affect the stage's
result, and a replayed or restarted run does not reproduce it — a killed
worker's final frames are simply absent.

### Waiting on the ledger stream

`kata events` tails the node's ledger transitions, one JSON event per line
(`--filter-execution`, `--status` and `--since <seq>` narrow it), until interrupted or the
stream closes. `kata events --exit-on <status>...` instead
waits for the first transition whose status is in that set, prints it and exits 0; the set
is the wait's own server-side status filter, so `--status` beside it is refused as a usage
error (exit 2) naming both flags. A wait whose stream ends before a match exits 65 —
whether the stream closed or ended on an error (the main's `event: error`, a lagged
subscription, a malformed frame, a transport cut), which is named on stderr; resume it with
`--since <seq>`. A `--since` past the node's ledger head exits 66.

### Cancelling a run

`kata run cancel <execution-id>` first fixes the run's outcome as `cancelled`, durably,
with your reason. From that instant no further stage of the run is started:
a run with nothing running at that moment — not started yet, or between two stages — ends at
its next stage instead of running on, and a node that restarts afterwards ends it rather than
resuming it (one still waiting on work that was already running is resumed only to wait for
that work, and then ends). A second cancel changes nothing, and the first reason stands. A
reason longer than 16 KiB is kept cut to that length, ending ` [truncated]`. A
run that had already decided its own outcome before your cancel arrived keeps it: the
cancel succeeds and changes nothing.

Work already running when you cancel is asked to stop. The cancel reaches
every kind of work it can hold, with one exception: a capsule stage that had been started but
not yet handed to a worker at the instant of the cancel is not asked — it is handed over after
and runs to its own end, and the run ends after it:

- a parked `sleep()` or a waiting blocking human request is ended in the main itself — the
  response counts them in `main_side_settled` — and the stages waiting on it never run;
- a running capsule is asked to stop, fenced to its attempt (`assignments_asked_to_stop`),
  and its container is killed; a `loop(..)` whose member it is ends once that member does,
  and starts no further member;
- an approval gate still waiting is settled `cancelled` in the main itself, PROVEN NOT
  PERFORMED — it never held a worker, so no stop is asked or recorded, and the response
  counts it in `main_side_settled`, not in `assignments_asked_to_stop` (the `cancel`
  operation's `stop_requested` stays `false` for it);
- every child a subworkflow stage waits on is cancelled, and their children in turn
  (`child_executions_cancelled`, which also counts a child that had already decided its own
  outcome — that outcome stands). Each child's outcome is fixed as `cancelled` first, so a
  child with nothing running at that instant — not started yet, or between two stages —
  starts nothing more and ends too; work a child had already started is handled as above,
  exception included.
  A parent whose outcome is decided while a child still runs — a sibling stage failed —
  cancels that child too, and a node that restarts in the middle of that still ends both.

A stage that was already running and finishes as the cancel lands keeps its recorded result.
Whichever of these the cancel reached, the execution's recorded outcome is `cancelled`, and
so is each cancelled child's. `kata run show` serves a cancelled execution's `status` as
`cancelled` — distinct from `failed`, and a non-zero exit on `kata run wait`/`watch` all the
same (an operator's stop is not a success). A run's outcome, once published, also ends any
sleep, request or subworkflow wait it still holds, so no wait outlives its run.

### Promoting a run by hand

`kata run promote <execution-id>` (also `POST /api/v1/executions/<id>/promote` and the
`promote` operation; `kata mcp` serves no promote) fast-forwards the trunk the run froze
onto a completed isolated run's candidate. It moves nothing unless the run's lifecycle is
`completed` and its checked program declares at least one REQUIRED validation criterion,
each reported passed (or waived by policy) for the candidate's tree by the deterministic
stage that declares it. A program that declares none is refused `promotion requires at
least one required validation criterion declared by the checked ExecutionProgram`; an
unsatisfied criterion is refused naming it (`validation_criterion:<id>:<why>`), and a run
that is not `completed` naming its lifecycle. Each answers HTTP 412, op code `conflict`, CLI exit 4,
with nothing moved. An id no execution was admitted under (it has no lifecycle record) is
absent, as `kata run show` finds it: HTTP 404, op code `not_found`, CLI exit 3. The refusals at landing itself (`target_trunk_renamed`,
`target_trunk_raced`) are listed with the other target refusals.

### Workspace effects

A `workspace_effect` stage is a typed VCS op — park, promote, commit, or forge export —
run against the execution's jj workspace. It runs IN THE MAIN as a durable
typed operation: claim committed, the op's jj transactions performed (each tagged
`kata.effect = <attempt>`), the outcome resolved — and a main crash mid-effect is
reconciled from the repository itself on the next drive, never replayed blind. A
`park` that wrote its parked ref, or a `promote` that landed on trunk, before the crash
but had not yet removed the execution's workspace, or had removed it only in part, is
finished on that drive: the rest of the workspace is removed, then the effect is
recorded — even when the workspace's working copy can no longer be loaded, since the
parked ref or trunk answers it. When the facts that answer whether an effect ran cannot be
read on that drive — the repository or the remote errs, or the frozen trunk was renamed
away since — the effect is recorded failed with `workspace_effect_unclassified` and the
error: whether it ran is unknown, so check the trunk, the parked ref or the remote branch
yourself. It is never re-run, and nothing is removed. A drive of the run makes that
record. A restarted main first asks whether the run's workspace is live and, when it is
gone, whether a pending `park` or `promote` published; an error from either refuses the
restart instead (below). A `promote` whose landing parked a
rebased candidate for revalidation (the base advanced) is recorded failed with that
refusal and its workspace removed, whether or not a crash fell before the removal —
provided the frozen branch still holds the park's base and nothing moved the workspace's
working copy meanwhile; otherwise recovery records the effect diverged and removes nothing.
That recovery reads the branch the run froze, even when the host's trunk has moved or been
renamed since. A run's closeout never parks its candidate over a `parked/<exec-id>` that
already names another commit (such as a landing's revalidation park): it refuses
`parked_ref_occupied`, keeps that ref and the workspace as they stand, and closes the
run out unparked. That refusal — like the closeout's `oci_candidate_diverged`,
`oci_candidate_disk_diverged` and `repository_torn` (the repository lost the workspace's
commit, or a tree or file of it, to a power loss; see "After a power loss" below) — is
recorded on the run before its
outcome is published:
`kata run show <exec-id>` and `GET /api/v1/executions/<exec-id>` serve it as
`evidence.closeout_park_refusal` (`refusal`, the `parked_ref` it would have written, and
the provider's `message`; for `parked_ref_occupied` it names both commits), and the
closeout records no parked candidate. A main that crashes before the record asks the park
again at its next boot and records that answer; once recorded, the refusal is the
closeout's answer for good, and the `parked/<exec-id>` it names is never adopted as the
run's park. An operator park (`POST /api/v1/executions/<exec-id>/park`) of that standing
workspace with no `ref_name` refuses the same way, and with one parks the candidate at
`parked/<ref_name>` and removes the workspace. Once the workspace is gone (the terminal
reaper removed it), a park with no `ref_name` still refuses `parked_ref_occupied` beside
the recorded refusal, since nothing remains to park. The operator park's refusal is its
response, not a record on the run. A
`promote` whose landing parked on a conflict and crashed before the removal lands again
on that drive: over an unmoved trunk that is the same conflict, parked ref and refusal;
if the trunk moved meanwhile, the second landing's answer is the one recorded.
A main restarted while an isolated run still runs resumes it on its live workspace, or
without one when the run's own record accounts for the workspace being gone: a `park`
or `promote` of the run completed; a `park` or `promote` is still pending and the
repository shows it published (the parked ref at the commit it parks, trunk holding the
delivered commit, or the landing's own revalidation park); or a stage ended without
completing and `parked/<exec-id>` exists. So a main killed between `promote` and
`export` — after the push and before the PR included — restarts, the export reads
the remote back, and the PR is opened once. Any other missing workspace
refuses the restart (`worktree isolation failed: Running isolated execution <exec-id>
has durable history but no live workspace, and nothing it recorded accounts for
that…`): a workspace removed beside only `commit` or `forge_export` effects, or beside
a `park`/`promote` that never published, is a removal the run did not make. A workspace
lookup that errs refuses the restart too (`…inspect workspace for Running isolated
execution <exec-id>: …`), and so does a missing workspace beside a pending `park` or
`promote` whose facts cannot be read — the frozen trunk renamed away since, say —
naming the error
(`worktree isolation failed: read the workspace effects of Running isolated execution
<exec-id>: …landing base bookmark <branch> is absent or conflicted`), and the attempt
stays pending, recorded nothing; once the branch the run froze reads again under its
name, the next restart answers the effect and finishes the run. A `commit`
op finalizes the execution's candidate as a commit described `kata workspace_effect commit
for execution <exec-id>` (kept reachable as `exec-<exec-id>`) and leaves an empty working-copy change
on top of it — trunk itself moves only through
`promote`. After a `commit`, `park` parks, `promote` lands and `forge_export` pushes
that committed commit, never the empty change above it, so `parked/<exec-id>`, trunk's
tip and the PR head carry the description. An effect stage requires the isolated worktree (`worktree_isolated =
True`): `kata workflows check` refuses one without it under `oci`. Under `oci` the
effect refuses rather than act on a workspace whose disk or candidate disagrees with
what the run recorded (`oci_candidate_disk_diverged`, `oci_candidate_diverged`) — a
foreign edit is never published as the execution's own — and `promote` refuses
`oci_delivered_tree_diverged` when the commit it would land does not carry the tree
validation judged. A `forge_export` stage must have a `commit` or a `promote` among
its ancestors, directly or through other stages; `kata check` refuses one with neither
(`forge_export_without_commit`). `forge_export` pushes only the
`kata/<execution>` branch, and records each of its two outside effects — the push and
the pull request — as an intent before it sends it, so after a crash kata knows which of
them might have happened and asks the remote instead of you (below). After a `commit` it
exports only that committed commit, or the
commit a `promote` of the run landed: when a writable stage between the `commit` and
the export changed the candidate and no `promote` landed the change, the export is
refused `forge_export_uncommitted_candidate` and nothing is pushed — put a `commit`
after the last stage that writes `/work`. An export is also refused, with nothing written
or pushed, when the commit it would push carries a conflict (`forge_export_conflicted_commit`)
or an author or committer kata will not publish (an empty identity, or kata's own agent
sandbox identity), or when the workspace still stands and its disk or candidate moved
(`oci_candidate_disk_diverged`, `oci_candidate_diverged`) — on every path to the push: the
stage as it runs, an approved `approval = True` gate, and a recovery after a crash. A
read-only stage between them changes nothing and the export proceeds. A `forge_export` names no remote and no base: the PR's
base is the run's frozen landable branch (its trunk, by the name admission resolved),
and the branch is pushed to the remote `git push` on that branch would use
(`branch.<branch>.pushRemote`, else `remote.pushDefault`, else `branch.<branch>.remote`),
else the repository's only remote. kata never guesses one: with neither, or with a
push remote that is a URL or no configured remote, the export is refused
`forge_remote_unresolved` before it is claimed, with nothing written or pushed. The
claim records the NAME of the remote it resolved, so a recovery after a crash pushes to
and reads back the remote of that name even if the keys above changed meanwhile; that
remote's URL, and the pull request's repository read off it (below), are read again at
each call, as `git push` reads them.

Before the push, kata reads the head of `kata/<execution>` on that remote (`git
ls-remote`) and pushes only over the head it read
(`--force-with-lease=refs/heads/<branch>:<head>`). It pushes the export's commit by its
object id, never through a local ref, and pushes nothing else: moving the local
`kata/<execution>` yourself, creating a branch or tag named as the commit's id, a `git
replace` of the commit, a graft in `.git/info/grafts`, and your
`push.followTags` and `push.recurseSubmodules` settings do not change what is pushed: the
commit, and the objects it reaches. A remote that does not answer that read fails the export
`forge_export_remote_unread`, with nothing pushed. A branch there that holds neither
nothing, this export's commit, nor the commit this run last pushed there is someone
else's — a branch reset to an older push of the run counts as someone else's too: the
export is refused `forge_export_diverged` and nothing is pushed over it.
Before it opens the pull request, kata asks the forge for an open pull request from
`kata/<execution>` into the frozen base branch (`gh pr list`; one into another base is
not the export's, and neither is one from a fork's branch that happens to share the
name): one found is adopted, nothing opened, and a forge that does not answer, or that
lists 100 open pull requests on the branch without the export's, fails the export
`forge_export_forge_unread`, with no pull request opened and the pushed branch standing.
Every `gh` call the export makes — that lookup, the create and the check below — names
its repository with `--repo`: the one the push remote's configured URL names
(`remote.<name>.pushurl`, else `remote.<name>.url`, read as written, before any
`url.*.insteadOf` rewrite), so the pull request opens where the branch was pushed, never
in `gh`'s default repository (`gh repo set-default`, `GH_REPO`, or `upstream` ranked
ahead of `origin`). A push remote whose URL names no `HOST/OWNER/REPO` — a local path, a
`file://` URL, a deeper path — refuses the export `forge_export_repository_unresolved`
before anything is written or pushed; the refusal shows the URL by its host and path,
never its user name or password. Before the push, kata then asks `gh` to confirm that
repository (`gh repo view <HOST/OWNER/REPO> --json nameWithOwner`, read-only): an
answer naming any other repository, or no answer, refuses the export
`forge_export_repository_unaddressed`, again with nothing written or pushed. The URL is
read as written and kata translates no host, so a URL `gh` cannot address is refused
there, before the push: an SSH host alias (`git@github-work:o/r.git` is host
`github-work`), a shorthand only a rewrite expands (`gh:o/r` is host `gh`), a repository
renamed since the URL was written. Give the push remote a URL `gh` addresses, e.g.
`https://github.com/<owner>/<repo>.git` or `git@github.com:<owner>/<repo>.git`. The push uses git's credentials for that remote and the pull request `gh`'s own
login; kata checks neither against the other.
The pull request's body ends with an HTML comment naming the intent
(`<!-- kata-forge-intent: <attempt>/<index> -->`; GitHub keeps it in the body and does
not render it); leave it there. When a crash or a failed command leaves an effect's outcome
unknown, kata asks the remote: for the push, `kata/<execution>` holding the pushed commit
means pushed, still holding the head kata read means not pushed (the push is sent again
after a crash; after a push that failed, the export fails, nothing sent again), and any
other head means kata cannot tell; for the pull request, a pull request on the branch
carrying its marker, open, closed or merged, and not from a fork, is adopted as the one kata opened, none
means not opened (opened again after a crash; after a create that failed, the export
fails), and more pull requests on the branch than the listing reads means kata cannot
tell. An effect kata cannot tell about is recorded failed with
`workspace_effect_unclassified` and is never sent again: check the remote branch and the
forge's pull requests yourself. A remote or forge that does not ANSWER that question
(unreachable, an expired `gh` login, an outage) settles nothing: the export stays
pending and the execution `running`, and kata asks again once a minute has passed since
the last unanswered ask, recording the effect `workspace_effect_unclassified` at the
tenth. `kata run show` does not show an export's attempt; `kata run forge-reconcile
<execution>` does: once the remote or `gh` is fixed, it asks at once and prints each
export as it then stands (its state, unanswered reads and last read error);
it refuses an execution with no pending export (`forge_reconcile_nothing_pending`), and
one whose lifecycle is not `running` — an admitting or finished run — with `reconciling
forge exports cannot dispatch after workflow terminalization`; both answer op code
`conflict`, CLI exit 4, and change nothing. Two
cases read wrong, and kata states them rather than
guards them: a `kata/<execution>` moved back to the head kata read, or deleted when kata
found none, after kata's push landed and before kata's first answered ask reads as not
pushed, so the push is sent again; and
a pull request whose marker someone deleted and that is no longer open is not
recognized, so a second one is opened. kata also assumes that a crashed main's `git push`
or `gh` died with it, as kata's service unit makes it: a main killed outside the unit can
leave one running that lands after the restarted main read it as not sent. A main
performs one workspace effect at a time across all its executions, and an export keeps
that turn while it talks to the remote: a repository check, the push, the pull-request
lookup, the create, and the pull-request listing that follows a create that errs (300 s
bound each), and the remote read before the push and the one that follows a push that
errs (60 s each) — up to 1620 s, about 27 minutes, or about 28 when a restarted main
first asks after a push its crash interrupted and pushes again — during which every other execution's effects, the effect gates you decide, and
`kata run forge-reconcile` wait. The push and
every read of the remote never wait on a prompt: git's own prompt is off (`GIT_TERMINAL_PROMPT=0`) and the ssh
command git would have run (`GIT_SSH_COMMAND`, else `core.sshCommand`, else `GIT_SSH`, else
`ssh`) runs with `-oBatchMode=yes` appended, so it must be an OpenSSH-compatible client, an
ssh remote's key must be usable without a passphrase prompt (an agent-held key) and its host
key already known; a remote that would prompt fails at once. A `forge_export` stage with
`approval = True` parks before anything is pushed, and `kata approvals` (and `GET
/api/v1/approvals`) shows under `workspace_effect` where the push goes: `forge_remote`,
the remote the claim recorded, whose URL also names the repository the pull request
opens in, and `forge_base`, the frozen branch the pull request
opens into, beside the op, the `kata/<execution>` branch and the candidate. Commits kata writes through jj carry jj's `change-id` header (jj's
`git.write-change-id-header` default, which kata inherits); git and GitHub ignore it.

### A representative agent workflow, end to end: `agent-change`

`workflows/std/agent-change.star` is the reference agent pack — one agent
turn inside a real container, a required validation criterion, a bound approval
gate, and the commit → promote → forge-export effect chain. It exercises every
machine the engine has. Walk one run:

```text
kata check agent-change
```

`check` compiles the pack and judges it against THIS node's declarations — the
`implement` stage is admitted only because the node declares
`[agents.change-agent]` with a nanocode `adapter` and a `credential` (a node
that doesn't gets `adapter_undeclared`, named).

```text
kata run agent-change --submit
kata run show <exec-id>
```

`implement` dispatches to a worker as a capsule: the embedded harness runs the turn
in the worker and every tool call inside the container, `/work` is the attempt's
materialization of the run's durable work head, and the turn's delta is judged against
`produces_files` before it is adopted on the main — a write outside `src/` or `tests/`
fails the stage. Its `edit` profile is `net = "offline"`: the capsule reaches nothing,
and the harness's model calls leave from the worker. `show` records the stage's
`token_usage` and the provider-reported `model_reported` (the provider's account, not
what was asked).

The delta is ignore-aware: untracked paths the workspace's own `.gitignore`
rules exclude — `target/`, `node_modules/`, build output — are never part of
the change, so they do not carry forward to later stages either (a test stage
starts from the adopted head and rebuilds them; a tracked path counts whether
or not a pattern matches it).

`test` is a deterministic shell stage running the fixture's own `tests/check.sh`
against the same workspace; its `status` is both the criterion's evidence and the
route. `approve` then parks the whole run `AwaitingApproval` BEFORE any mutation:

```text
kata approvals
```

shows the parked gate bound to the approve capsule — its id, argv, the mapped
work tree, the declared write scope — exactly what the decision authorizes:

```text
kata run approve <exec-id> <assignment-id>
```

resumes the run into `commit` (the candidate is finalized as a described commit
inside the workspace), `promote` (trunk fast-forwards onto that commit and the
worktree tears down — the candidate's tree is re-read against what validation
stamped; a diverged candidate is refused, `candidate_tree_mismatch`), and `export`
(pushes that same commit to `kata/<exec>` on the remote `git push` on the run's trunk
would use — `branch.<trunk>.pushRemote`, else `remote.pushDefault`, else
`branch.<trunk>.remote` — else the repository's only remote, and opens the PR into that
trunk through the node's forge). A reject at the gate fails the run: nothing is committed or pushed, and
the candidate auto-parks at `parked/<exec-id>` for inspection.

The same pack survives interruption by construction — kill the main or the
worker at the parked gate and restart; the gate is rediscovered and resumed. Kill
the worker mid-turn and the attempt settles `PROVEN AMBIGUOUS` (the container's
outcome is unobservable), terminal — never re-delivered. `just live-nanocode` runs
the pack on the embedded harness, offline, to the fixture's local bare remote: `nanocode_openai` on kata's own ChatGPT login
(`kata login openai`) and `nanocode_anthropic` on `env:ANTHROPIC_API_KEY`, which that
recipe's environment must carry. Beside it run one real turn in a real capsule (a shell
command, a patch and a structured answer, the delta committed), the worker killed while
a model request is outstanding and while a tool runs, the main killed with its supervised
node's turn outstanding and restarted, an operator cancel, and a measurement of
nanocode's empty-response re-prompt. Every interruption settles as above; the no-spend twins, against a mock
model that logs a request and never answers, ride `just oci-live-smoke`, beside the
measurement's positive control (a mock that answers one empty response). The pack's own
live cells are `agent_change_live`, `oci-live-smoke`'s fourth step: the pack on
`nanocode_openai` against a scripted mock model (no spend; its tool calls run in the
turn's real container) to one PR, the kills and the reject above, a cancel mid-turn, a
fallback panel's retry, an agent fix loop, a priced turn crossing a `cost_bound`, worker
liveness under SIGSTOP, a `model_reuse` stage adopting an earlier run's turn, and a
model connection the provider cuts mid-response after the turn's command ran: the
attempt settles PROVEN AMBIGUOUS, is never re-run, and publishes nothing.

`workflows/std/checked-command.star` is the same workflow with no agent in it —
the representative CHECKED-COMMAND twin: `implement` is a deterministic shell
stage whose `run=` names the repository's own change command,
`tools/implement.sh` — the repo commits the script, and its writes are judged
against the stage's declared `produces_files` fence — and `test`, `approve`,
`commit`, `promote`, `export` are the same stages with the same bound approval
and typed effects (`kata check checked-command`; `kata run checked-command
--submit`). It declares no `[agents.*]` — a node offers it nothing but a shell
capsule and a busybox environment. Its live cells are `checked_command_live`,
`oci-live-smoke`'s fifth step.

### Implement, test, fix, approve and open a PR: `change`

`workflows/std/change.star` turns a task text into a tested, human-approved change:
committed, landed on the local trunk, and exported as one pull request into it.

```text
kata check change --config .kata/kata.toml
kata run change --param task="$(cat brief.md)" --param test_command="sh tests/check.sh" \
  --watch
kata approvals
kata run approve <exec-id> <assignment-id>        # or: kata run reject <exec-id> <assignment-id> <reason>
```

Its two params are required: `task` (up to 64 KiB) reaches both agent prompts, and
`test_command` (up to 4 KiB) is what `test` runs, passed to `sh -c` as one
single-quoted word (`shquote`). Its stages:

- `plan` — an agent turn (`agent = "default"`) over `/work` at the run's target (its
  prompt names `{{ target.branch }}` and `{{ target.head }}`) under `workspace =
  "ro"`: `/work` is writable while the turn runs, and a turn that leaves a change
  there fails `work_delta_out_of_scope` with nothing of it applied (an untracked path
  the repository's `.gitignore` ignores is discarded instead). It answers a typed
  `Plan` (summary, steps, files, risks).
- `implement` — an agent turn over a writable `/work`: it carries out the task. It is
  the body of a `loop()`.
- `test` — a shell stage over `/work` under the same `workspace = "ro"` (a command
  that leaves a change in `/work` fails the stage, except under an untracked path
  `.gitignore` ignores, which is discarded) that runs the test command, writes
  its output to `/out/test.log`, and reports a typed `TestReport`: `status`
  (`passed`/`failed`), `exit_code`, `feedback`, and the `tests-green` criterion's
  result. It is the loop's gate, the required validation criterion and the route's
  source. `feedback` is the output's last 4000 bytes, made safe for a JSON string
  by turning every byte that is not printable ASCII, and every `"` and `\`, into a
  space — lossy on purpose, so any test output yields a valid report.
- `approve` — the human gate: the run parks before anything is committed.
- `commit`, `promote`, `export` — the candidate becomes one described commit, trunk
  fast-forwards onto it, and the same commit is pushed to `kata/<exec-id>` with one
  PR into the run's trunk opened through `gh`.

The pack runs against a trunk target (the default, or `--target trunk`), whatever
the trunk is called: the PR's base is the branch the run froze, and the push goes to
the remote `git push` on that branch would use (`branch.<trunk>.pushRemote`, else
`remote.pushDefault`, else `branch.<trunk>.remote`), else the repository's only
remote. A `pr:<N>` target is refused `target_not_landable` before the forge is read,
and a repository that names no single remote is refused `forge_remote_unresolved` at
`export`, with nothing pushed.

The loop runs `implement -> test` up to four times; each `implement` after the first
sees the previous test's `feedback` as `{{ review.feedback }}`. A passing test routes
to `approve`. A loop that runs out (`on_exhaustion = "accept"`) routes its last,
failing report to `park_unfinished`, which parks the candidate at
`parked/<exec-id>` and lands nothing; the run completes. At the gate, `kata approvals`
shows the run's frozen target and its `task` and `test_command` beside the capsule. A copy
of the pack that adds a
per-loop `bounds=` whose limit trips before a test reports routes nothing instead, and
the run's closeout parks the candidate at the same ref. Rejecting at the gate fails
the run with nothing committed, and the candidate auto-parks. If the execution
workspace on disk was edited while the run waited at the gate, `commit` refuses
`oci_candidate_disk_diverged`: nothing is committed, landed or pushed, and the
workspace stands for inspection.

Limits, stated in the pack: every capsule is authored `net = "offline"`, with a
512 MiB memory ceiling, `/tmp` charged to it, and 64 pids, and every capsule — a
shell stage's and a nanocode agent stage's alike — is offline: the harness's model
calls leave from the worker. A test command that needs the network, more memory or
more threads (`cargo test` on a real crate) does not fit; a dependency-free suite
does. The `verify` profile requires `sh`; a test command needing another program
needs a copy of the pack. It ran on real models in the counted round (`change` three
times to a delivered pull request and once on its fix loop's refine cell). Its live
cells are `change_live` (`oci-live-smoke`'s sixth step), on `nanocode_openai` against a
scripted mock model: the fix loop to one PR, one PR into a repository whose trunk is
`master`, the exhaustion park, the closeout park of a loop a per-loop bound cut short,
the on-disk mismatch refusal, and an operator promote onto a renamed trunk refused as a
conflict on every face, each read from git, the bare remote and the fake `gh`'s
record.

### Review a pull request or the trunk: `review`

`workflows/std/review.star` answers a typed code review of one target. It writes
nothing: no branch, no remote ref, no forge comment.

```text
kata check review --config .kata/kata.toml
kata run review --target pr:42 --watch
kata run review --watch                              # the trunk head against its first parent
kata run output <exec-id> verify                     # the final review
```

With `--target pr:<N>` the run reviews pull request N: `/work` is its head and the
change is the range from the merge base with its base branch (see "What a run works
on: `--target`" for how kata reads and fetches it). Without `--target` the run
reviews trunk's head against its first parent. Its one param, `focus` (up to 4 KiB,
default empty), is a line the operator adds to both prompts: `--param focus="the
error handling"`. Its stages:

- `find` — an agent turn (`agent = "default"`) over `/work` at the target head,
  with its git history, under `workspace = "ro"`: the capsule's `/work` is writable
  while the turn runs, and a turn that leaves any change there fails its stage as
  `work_delta_out_of_scope` with nothing of it applied. The prompt carries the frozen head, the merge
  base and the `git diff` command for the range, the changed files, and for a pull
  request its number, url, title and description — the title, description and file
  names framed as UNTRUSTED text, never as instructions, each rendered through
  `untrusted` so every line of it starts with `> `: a description that writes the
  frame's end line or a "Note from kata" line cannot end the frame or pose as kata.
  It answers a `Review`.
- `verify` — a second agent turn over the same `/work`, given `find`'s review: it
  re-checks each finding, drops what it cannot confirm, corrects a wrong line, and
  gives the final verdict. Its `Review` is the run's answer.

A `Review` is `{verdict, summary, findings}`: `verdict` one of `approve`,
`request_changes`, `comment`; `summary` up to 4000 characters; each finding
`{path, line, severity, message}` — a repo-relative path in the target head, a
1-based line (0 for the whole file), a severity of `blocker`, `major`, `minor` or
`nit`, and a message up to 2000 characters. The contract reaches the model in the
prompt, rendered by `json_skeleton` from the same contract `produces=` validates; on
`nanocode_openai` it is also sent as a
strict output schema rendered from that contract ("A stage's `produces=` contract as
the turn's output schema"). An answer that does not validate is asked again up to
twice (`validate_retries = 2`) before the stage fails. kata checks the answer's
shape; that a finding's line holds the defect is the reviewer's claim.

`kata run output <exec-id> verify` prints the `verify` stage's output; its `parsed`
member is the `Review`. The run's target pins under `refs/kata/targets/<exec-id>/`
are deleted once it is terminal.

Limits, stated in the pack: each turn's capsule is authored `net = "offline"`, is
offline (the harness's model calls leave from the worker), has a 512 MiB memory
ceiling and 64 pids, and the `review` profile requires `git`. The run is bounded at
one hour. It ran on real models in the counted round (three times on a pull request
with seeded defects and three times on a real third-party pull request). Its live
cells are `review_live` (`oci-live-smoke`'s seventh step), whose scripted mock model
answers what a reviewer script computes inside the capsule: a `pr:1` review through
the CLI and again through REST, and a trunk review, each answer validated against the
contract by the cell itself and its findings' paths read from `git ls-tree`, with the
remote's refs unchanged and the fake `gh` only read.

### Durable formats and upgrades

kata versions the durable formats below. `kata upgrade --dry-run --data-dir <dir>` previews
what a data directory holds before you start this binary on it.

- **The operational database is at schema 49** (it keeps per-effect intent rows only for
  a `forge_export`'s push and pull request, `forge_intents`, each counting the reads its
  observer's remote left unanswered and keeping the error its command returned, and no
  other permit table; an
  attempt has no failure-retry park: `attempts` carries no retry deadline or retry
  counter, and `awaiting_retry` is not an attempt state; an execution's work head
  records the commit its latest `commit` effect finalized, `committed_commit_id`; every
  isolated execution's invocation — envelope schema 3 — carries the target its admission
  froze, a pull request's with whether its title and body were cut; a git view records its branch ref as a name and the commit it points at; and a
  schedule firing records either the execution it submitted or the refusal of its
  target; a `forge_export` attempt records the push remote its claim resolved and no
  pack-written remote or base; every failed, cancelled or orphaned attempt that was
  dispatched records its charge, and a metering summary — a record's, a child
  summary's — carries the token count `tokens` and the stages whose count is unknown;
  a run whose closeout park was refused by name records that refusal; and a
  worker-reported failure records, beside its verdict, the class of the model provider's
  failure — `refused`, `transient` or none — which the stage's failure retry reads; a
  capsule settlement, a rejected capsule approval and a dispatch refused after terminal
  intent record their verdict — `proven_not_performed`, `performed_but_failed` or
  `proven_ambiguous` — in the same typed field a worker-reported failure does, and the
  failure retry reads only that field (a main-resolved failure — a rejected
  `workspace_effect`, a failed forge export — records no verdict and is never re-run); and
  its capsules are at execution contract 14, each naming a nanocode adapter and a
  `kata_login` or `env:` credential, and none declaring a proxy name or
  `XDG_RUNTIME_DIR`).
  A data directory at any other
  schema is refused at boot: `operational.db schema version <n> is not the clean runtime
  version 49; use a new empty data directory and preserve this directory offline`. A file
  with no stamp at all is refused naming both things it can be: `operational.db carries no
  schema stamp (version 0): either its first creation was interrupted before the schema
  committed, or it is an older or foreign file`, with the same recourse. `kata upgrade`,
  which reads the stamp whether or not the directory holds a `main-identity.json`, can meet
  either. Boot meets it only in a directory that holds its `main-identity.json`, where it is
  the second: kata writes the identity only after every store is created, so a directory
  whose first creation was interrupted has none. Boot of a
  directory with no `main-identity.json` refuses first, whatever it holds: `Kata data
  directory <dir> has no clean-format main identity and contains preserved entry
  "<name>"; refusing to reinterpret retired, interrupted, or foreign state. Use a new
  empty directory and preserve this one offline.` There
  is no in-place migration: start against a new, empty `[node] data_dir`, and keep the old
  one offline.
- **The delivery event log (`ledger_events.db`) is at schema 4** (a row is its delivery
  sequence, the serialized event and its timestamp). A file at any other schema is refused
  at boot: `event log schema version <n> is not the clean runtime version 4; use a new
  empty data directory and preserve this directory offline`.
- **The worker membrane store (`idempotency.db`) is at schema 2** (it holds the
  membrane identity and nothing else). A file at any other schema, or of another shape, is
  refused at boot (`idempotency.db has unsupported schema stamp <n>; expected 2`), and a
  recovery artifact whose worker receipts or captured stores name another schema is
  refused at restore.
- **The native memory store (`memory.db`) is at schema 3.** A file at any other schema
  is refused at boot: `memory.db schema version <n> is not the clean runtime version 3;
  use a new empty data directory and preserve this directory offline`.
- **Checked programs are at schema 11** (a stage's failure-retry budget is its agent
  fallback panel; the checked policies carry no retry policy; a `forge_export` stage's
  directive carries only its PR `title` and `body`; a workflow's or a loop's `bounds`
  may carry a `tokens` bound). Every checked-program
  schema bump also bumps the operational schema, so a program at another schema exists
  only in a data directory this binary already refuses at boot, whatever state its
  executions are in — finishing or cancelling them first does not help.
- **The execution contract is at version 14** (an agent capsule's turn names no proxy
  spelling — `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, each in both casings —
  and no `XDG_RUNTIME_DIR`, in its env or as its `env:` source; version 13 made the turn
  name one of the two nanocode adapters and a `kata_login` or `env:` credential, the vendor adapters and
  the host logins they read being gone; version 12 made a capsule's git view name its
  branch ref with the commit it points at, read off the execution's frozen target, or
  none; version 11 added the confined `/work` view a `reads=` stage carries). It
  is part of every capsule's identity, so no result produced under another contract is
  ever reused by the content cache.
- **The content store only grows.** `cas.db` and the `cas/` blob tree carry no version
  stamp; `cas.db`'s table shape is checked on every open, and a file of another shape
  (`cas.db has column contract …`) is refused — start against a new, empty `[node]
  data_dir`. Boot refuses a `cas.db` without its `cas/` tree before opening any store:
  with a `main-identity.json`, as `clean engine restart is missing required authority
  asset(s): cas/; refusing to create empty replacements`; without one, as the
  identity-less directory above. The content store's own open (`CasStore::open`, which
  boot reaches only past that check) names both causes it cannot tell apart — a first
  creation interrupted before the tree was made, or a lost tree — with the new-empty-
  directory recourse; `kata upgrade` does not read the content store. kata has no
  content-store collection: an object, once written, stays for the life of the data directory — including an orphan a crash left unreferenced, and
  what an attempt that ran and failed published, which no record names: a command's
  captured stdout, stderr and `/work` delta (its manifest and member objects), and, for
  an agent turn that completed but whose result the main refused, its `/work` delta
  (manifest and members), its response and its nanocode session evidence.
- **Backups are at manifest version 2, recoverable backups at 7.** `kata backup`
  writes a version-2 data snapshot for `kata restore`; `kata backup --recoverable`
  writes a version-7 recovery artifact for `kata restore --recoverable`. Restore reads
  exactly those two and refuses any other version before decoding the artifact: an
  older one needs a new backup taken with this binary, a newer one needs a newer binary.

**Boot and `kata upgrade` block on one set of programs.** In a directory at the current
operational schema, a checked program this binary cannot dispatch (bytes that do not
decode, or a stage execution class this build cannot honour) blocks both boot and
`kata upgrade --apply` while its execution is admitting, running or terminalizing, and
both name it with the same reasons. A finished or cancelled execution's program is
retained evidence and blocks nothing; its execution record carries a
`checked_program_unreadable:` warning. Finish or cancel the blocked executions on the
binary that wrote them, or start against a fresh `[node] data_dir`. A directory at an
older operational schema is refused by its stamp before any program is read, whatever its
executions' state, and `kata upgrade --dry-run` reports it as a non-current format rather
than listing programs; one at a newer schema is refused outright. A directory holding a
database this binary does not write (a top-level `*.db`, or its `-wal`, `-shm` or
`-journal` file, outside the set it declares) is refused the same way, at boot and by
`kata upgrade`, naming the file: nothing in the directory is opened or deleted. Start
against a fresh `[node] data_dir` and keep the old one offline.

### After a power loss: the repository

A run's repository writes — its target pins under `refs/kata/targets/<id>/`, its
workspace's commits and checkout, each `/work` apply, each workspace effect's commit and
ref, a park, a landing on trunk, a `forge_export`'s local branch, a workspace's teardown,
a pin's release — reach stable storage before anything kata records depends on them:
the provider calls `syncfs(2)` on the filesystems holding the repository (its root and
its git store) before the call answers, and before every jj operation it publishes after
writing git objects or refs. jj syncs its own operation, view and index files, but the
gix library it writes git objects and refs with syncs none of them, and git syncs only
packs by default, so without that a host power loss can empty the files written in the
seconds before it — measured: the
target pin, jj's keep refs and the workspace's commits came back zero-length under an
admitted, dispatched run, and the restarted main exited. kata's own `git` commands also
run with `core.fsync=loose-object,reference`. A `syncfs` that fails is refused by name,
`repository_not_durable`, and nothing that depends on the write is recorded. The cost is
one `syncfs` per such write: it waits for every dirty page of that filesystem, so a
filesystem other heavy writers share makes those steps slower.

At boot, before anything else touches the repository, the main repairs what a power loss
tore after the last sync, and logs at WARN what it did: it removes every EMPTY loose
object (git and gix skip writing an object whose file exists, so an empty one would
stand in for it forever), rewrites a torn `refs/jj/keep/<id>` at `<id>` or deletes it,
and rewrites a torn branch at the commit jj recorded for it only when kata wrote it
last: one of kata's own branches (`parked/…`, `exec-…`, `kata/…`), or a branch whose
newest reflog entry is jj's export of that commit (trunk after a kata landing). A torn
kata branch jj never recorded is deleted. Every other torn ref — a branch your git moved
after kata's last import, or whose reflog says nothing kata can read, and any torn
remote-tracking ref or tag — is left alone and named in that WARN line as
`repository_torn`, because the commit jj recorded may be older than your last write:
repair or delete it yourself (its reflog, `git reflog show <ref>`, names your last
commit; `git update-ref -d` refuses a broken ref; remove its file under `.git/refs/`).
One case is rewritten anyway: when the power loss emptied your branch AND dropped your
newest reflog entry with it, and the entry before it is kata's export, the branch is
rewritten at kata's commit — check a branch you committed to just before the outage. The
target-pin sweep then deletes the pins of executions that no longer own them, torn or
not, and rewrites a live execution's torn pin at its recorded target (`target pins: boot
sweep re-derived …`). A commit the repository's view still names but its store lost —
a disk that dropped a synced write — is refused `repository_torn` where kata reads it,
and so is a workspace candidate whose tree or files the store lost under an intact
commit, before anything parks, lands or removes it: a run's closeout records it as
`evidence.closeout_park_refusal` and closes the run out, leaving its workspace — the one
copy of those files — in place for you. Not repaired, stated: a loose object a power loss
left non-empty but unreadable (a filesystem that zero-fills instead of truncating) — `git
fsck` names it; delete it and the next write of that object writes it again. And on a
filesystem that does not protect a rename over an existing file (xfs, or ext4 mounted
`noauto_da_alloc`; ext4's default protects it), a power loss in the middle of a pin's
release, the boot sweep or the repair can empty `.git/packed-refs`, losing every packed
ref; `git fsck` names what is missing, and each branch's reflog under `.git/logs/` its
last commit.

## Run output

`kata run --wait` submits, waits for terminal state and prints the execution
record. Each stage's entry under `outputs` is its `capsule_result` record: `parsed`
is the JSON object the stage answered with, `content` is the stage's stdout verbatim (an
agent stage's response), and the engine's own facts sit beside them at the entry's
root — `exit_code`, `stop_reason`, `token_usage`, the agent turn's report under
`agent`, and the artifact references for the captured stdout, stderr and result
tree. The transcript below is abridged (`…`) to those keys. Under a `produces=`
contract `parsed` holds exactly the declared fields (an undeclared one fails the
answer's validation). Under a flat `outputs = {..}` table every declared output is
present and type-checked, and any other key the stage printed is kept in `parsed`
unchecked: the review loop's `{{ review.feedback }}` reads a reviewer's `feedback`
whether or not the reviewer declares it, and a whole-object `{{ stages.<id>.parsed }}`
renders every key.

```console
$ kata run std.hello --wait --timeout-secs 60
{"id":"<run-id>","workflow_name":"std.hello",…,"status":"completed",…,"outputs":{"hello":{"agent":null,"content":"{\"greeting\":\"hello from kata\"}\n","exit_code":0,"kind":"capsule_result","parsed":{"greeting":"hello from kata"},"stderr_artifact_id":"…","stdout_artifact_id":"…","stop_reason":null,"token_usage":null,…}},…}
$ echo $?
0
```

There is no separate `stdout` field. Do not declare engine facts in `outputs=`;
the closed-world output contract rejects fields the command did not produce.

Submitting is not idempotent: `POST /api/v1/executions`, which `kata run` and the SDK's
`run` methods call, takes no idempotency key. If the reply is lost after the main
accepted the run — the main died while answering, or the connection dropped — the run
is still admitted, and a main that restarts runs it to the end. Submitting again admits
a second run, so after a submit that got no answer, look for the first one with `kata
run list` before you resubmit.

### A non-zero shell exit FAILS the run — unless you say otherwise

The default `exit_policy="zero_success"` makes a non-zero shell exit fail the
stage, and its successors never run. Nothing extra is required for CI:

```python
boom = stage(id = "boom", run = "echo before-exit; exit 3", agent = "shell")
workflow("nonzero-exit", description = "non-zero shell exit fails the run", root = [boom])
```

When the exit code is information that the graph consumes, opt out explicitly:

```python
boom = stage(id = "boom", run = "echo before-exit; exit 3", agent = "shell",
             exit_policy = "content")
workflow("content-exit-probe", description = "a nonzero shell exit is content",
         root = [boom])
```

The latter completes and exposes code 3 at
`outputs.boom.exit_code`.

The main judges a capsule's exit status against the stage's `exit_policy` when the worker reports it: under the default a
non-zero exit fails the stage with the same `shell: command exited nonzero: exit_code=<n>`
reason (the stderr tail and the `exit_policy="content"` recourse included), the capsule's
`/out` result is not kept, and the stage's occurrence accepts no outcome. A process that
reported no exit status (killed by a signal or by the runtime, or run under a runtime
client that failed without finishing its own delete, so the status that client exited
with was its own) counts as exit `-1`. An
exit failure is not retried and does not spend the stage's
`validate_retries`: it is decided before any output is validated.

A stage whose output fails its declared `outputs` (or `produces=` schema) is retried up to
`validate_retries` times (default 2); a `null` on an optional `produces=` field is the
field being absent, not a failure (see "A stage's `produces=` contract as the turn's
output schema"). An agent stage's retry re-renders its
prompt with the validation error appended (`validate_feedback_template`); a shell
stage's retry re-runs its own command unchanged. Each retry is its own
container; the failed attempt's `/work` changes are kept, so the retry
starts from them, and an approval gate on the stage is not asked again for a retry. A
`loop(..)` member retries the same way, inside its iteration, and so does a `topology` stage's
root (its declared children, which ran beside it, are not re-run). After the run walks away
(see "Walk-away bounds") a retry is not dispatched: the stage fails, naming the walk-away
row and the validation error.

A stage that FAILS (rather than producing invalid output) is retried when it has a
failure-retry policy: an agent fallback panel (`agent = ["a", "b", ...]`) retries at once, with
no wait, on the panel's next member, one retry per remaining member. Every stage outside a `topology`,
single-agent or panel, and every capsule member of a `loop(..)`, also re-runs an agent turn its
model provider failed TRANSIENTLY on the same agent, twice, before any fallback — 30 s after the
failure, then 120 s after the second. Each retry is its
own container on the stage's retry chain, its prompt re-rendered from the durable inputs a
resume re-derives — the stage's declared template over the recorded stage outputs, never a
replay of the failed attempt's recorded prompt bytes — every panel member must be declared in
`[agents.*]` when the pack is checked, and a failure kata cannot rule out having had effects
(PROVEN AMBIGUOUS — a worker that died mid-run, a lost deadline) is never retried.

A nanocode agent turn its model provider failed is not one of those: kata classifies it from
the harness's own typed error and names the provider's error type and message in the
failure. A request the provider REFUSED with a 4xx error answer the harness does not retry
— an HTTP error response, or on the Responses WebSocket an `error` event stating the status
(`HTTP 400 invalid_request_error: Your credit balance is too low ...`, an invalid key, an
unknown model, a request too large) — records the class `refused`, is charged nothing when
it was the turn's one request, and its agent is never run again on the stage's retry chain:
a fallback panel skips that agent's later seats, and the stage fails naming the refusal
when only refused agents are left. A ChatGPT plan's usage quota (`usage_limit_reached`) is
`refused` on either Responses transport, whatever its status, its reason naming the quota:
the plan's limit resets on its own schedule, so no re-run outlasts it. A
`previous_response_not_found` answer is `transient`: a fresh attempt chains to no stored
response. A failure the harness classes transient (an overload, a
rate limit, a server error, a timeout, a dropped connection), reached once the harness's own
retries are spent, records `transient` and is re-run on the same agent, twice, in a fresh
container from the same base, on any stage outside a `topology` and on a `loop(..)` member
(at its member seat, with the same prompt, through the loop's own walk); a third transient
failure falls back to the panel's next member, fails a single-agent stage `after 2 re-run(s)
of a transient model provider failure`, or ends the loop on its member's failure. A
`topology` stage's root and children — a static topology serving as a loop member among them —
are not re-run: the topology lands each member's `/work` from its first attempt, and a member
accepted on a re-run would need that changed. A loop member is re-run under the plain
stage's verdict rule: one settled PROVEN AMBIGUOUS, or stopped by the operator, is not, whatever
class its failure recorded. Each wait is measured from the
instant kata recorded the failure, so a main restarted inside it waits only what is left (a
re-run that came due while it was down runs on the resume), and a graceful stop does not wait
it out, a plain stage's or a loop member's: the run is handed back to the restart. A cancel
does not wait it out either: the run ends then, its re-run never started. A re-run whose wait
would end past the run's `time_bound` is not run at all, since it could only end past the
bound: the stage, or the loop on its member's failure, fails at once, naming the bound (a
loop's own `time_bound` is judged as before, at its member's acceptance). An outage longer
than the harness's own retry window (seconds) and the two waits (two and a half minutes)
still fails the stage. Both classes are settled PROVEN NOT PERFORMED: an offline stage's tool calls
touched only its own container, and nothing of a failed turn is published. A stage with
`net = "host"` whose turn ran a tool call before the provider failed stays PROVEN AMBIGUOUS
— that call could have reached the network — and is never retried; so does a failure the
harness cannot place in either class (a stream event that states no HTTP status, a server
error it does not retry), and one on a turn kata had already asked to stop. A spent policy
fails the stage: `stage failed after exhausting ...`. After the run walks away the panel's
next member is not dispatched: the stage fails, naming the walk-away row and the failed
attempt's reason. A `loop(..)` member or a
`topology` stage with a failure-retry policy (a fallback panel) is still refused
when the pack is checked (`expansion_failure_retries_unsupported_under_oci`) rather than run
without it.

A capsule attempt is also never RE-DELIVERED: an attempt the main could not send — a delivery
the frame could not build, a placement or transport refusal, an authorization that failed after
claiming — is settled PROVEN NOT PERFORMED and left on the chain as a failed seat, not sent
again. That settled seat answers the retry rule above like any other failed attempt: a stage
with a failure-retry policy retries it, and one without fails — which is every `loop(..)`
member, since a member cannot author a retry policy (`expansion_failure_retries_unsupported_under_oci`),
so an unsent member attempt fails its expansion exactly as an unsent plain-stage attempt fails
its stage. (Nothing is re-sent — a re-submission of the stage authorizes a new attempt.)

A shell stage's captured output is bounded too, and a stage that prints past the bound
FAILS — its `content` would otherwise be a silently shortened stdout —
whatever its `exit_policy` and whatever it exited; its successors never run, and the
failure is never retried. The bound is the stage's OWN combined
stdout+stderr bound: `stage(output_bytes = N)` (default `CAPSULE_OUTPUT_BYTES`,
64 MiB, capped at `[node] output_bytes_ceiling`, 1 GiB) — the provider spools the
two streams to files under the attempt's `capture/` directory and KILLS the stage
when their sum passes it, so a stage that crosses the bound fails with
`shell: the capsule's execution provider KILLED this stage for exceeding its
combined capture bound` and its `/out` result is not kept; the spool files are
published as CAS artifacts (named on the frame as `stdout`/`stderr` artifact
references, execution-owned and retained like `/out`), and `content` is read off
the stdout artifact. A stage that needs more than the default authors
`output_bytes =` or writes the payload to a file under `/out` instead of
printing it. An `agent` stage's capture follows the
same rule with a different pair: the harness's response text and the tool
host's drained stderr share the stage's `output_bytes`, the response is bounded
while it streams and both are scrubbed of the turn's credential values before
any cut — so a model echoing its credential, or one whose answer plus stderr
outgrows the bound, publishes `[redacted]`/the bounded prefix and the frame
carries `capture_exceeded`, which the adoption judge fails as PERFORMED BUT
FAILED, exactly like a shell stage that printed past the bound. `work_delta_bytes=` and
`work_delta_entries=` declare the same kind of bound on the `/work` delta — the
files a stage may change relative to its input tree — carried on the capsule's
identity, bounded at admission by `[node] work_delta_bytes_ceiling` (1 GiB)
and `[node] work_delta_entries_ceiling` (100_000), and enforced when the delta
is captured: a stage whose `/work` edits cross either bound fails
`work_delta_bytes_exceeded` / `work_delta_entries_exceeded` with nothing
published (see "The `/work` delta after a capsule stage").

### When a stage fails, its siblings finish

A failed stage stops only what depends on it. Its dependents, transitively, are never
dispatched — a stage runs only once every dependency completed or was skipped — but every
other stage keeps going: a sibling already running (a capsule, a parked `sleep()`, a
subworkflow child) runs to its own end, and an independent stage that becomes ready later
still runs. The run ends `failed` once nothing is in flight, naming every failed stage
and the walk-away row, if one was recorded (`workflow completed with N failed stage(s):
…`, or `workflow stuck after N failed stage(s) blocked downstream: …` when dependents were
left unrun). A walk-away — a bound, a
halting `cost_budget`, a metering halt — skips the halted stage's dependents the same way
and stops no running sibling, but a sibling that finishes after it releases nothing: its
dependents are skipped too, and an independent stage that would become ready afterwards
never starts.

Two exits do not wait for siblings: a plain stage whose output still fails its declared
`outputs` after `validate_retries` ends the run at once (a `loop(..)` member or a
`topology` root settles its retries inside its expansion instead) — a subworkflow child still
running is then cancelled with it — and so does `kata run cancel`. kata does not cancel
running siblings when an ordinary stage fails; this is a deliberate product choice, not a
gap. A pack that wants fail-fast behaviour orders the
expensive stage after the check it depends on.

## Invocation params

A workflow declares the values a run is invoked with, and every stage's `prompt=` and
`run=` template reads them:

```python
fix = stage(id = "fix", agent = "shell", sandbox = "edit", run = """
printf '%s\n' {{ params.task | shquote }} > /work/TASK.md
printf '{"wrote": true}\n'
""", outputs = {"wrote": "bool"})
workflow("fix", root = [fix], worktree_isolated = True, params = {
    "task": field(string(max_length = 65536)),
    "focus": field("string", required = False),
    "token": field("string", secret = True),
}, sandbox_profiles = {"edit": sandbox_profile(workspace = "rw", net = "offline")})
```

```console
$ kata run fix --param task="$(cat brief.md)" --param token="$TOKEN" --wait
```

`--param NAME=VALUE` parses VALUE as JSON when it parses and as a string otherwise;
REST, MCP and the client take the same `params` object. The main resolves the set once at
admission (unknown names, wrong types and a missing required or secret param are
refused with a `param.*` code), fills the defaults, and binds the result into the
execution's admission digest. A restart re-renders a stage from that admitted set, so a
resumed stage renders exactly what it first rendered.

`{{ params.<name> }}` renders the supplied value or its default, and `none` for an
optional param nobody supplied (`{% if params.focus %}` guards it). A template is not
re-rendered, so `{{ … }}` inside a value is text. In a shell `run=`, pipe a value through
`shquote`: it renders one POSIX single-quoted word, so quotes, `$`, backticks, `;` and
newlines in the value reach the command as data. `shquote` refuses a `none` value at
render rather than quoting the word `none`.

`kata check` refuses two reads:

- `param_unknown_in_template` — `params.<name>` where the workflow declares no
  `<name>`, in any branch of the template, taken or not.
- `param_secret_in_template` — any read that could render a `secret = True` param:
  `params.<secret>`, and, when a secret is declared, the bare `params`, a subscript
  (`params["x"]`), an alias (`{% set p = params %}`) or a loop over it. A rendered
  prompt or command is durable and part of the stage's identity, so no template
  renders a secret param.

A subscript naming an undeclared param, in a workflow that declares no secret, is not
refused at check; it fails the stage's render at dispatch. `approval_reason=`,
`validation_criterion(commands=…)` and `forge_export`'s `title=`/`body=` are literals
and do not read params.

A rendered command or prompt is bounded, because it is written durably before it runs:
a shell stage's rendered `run=` is the capsule's argument vector and part of its
identity, and an agent stage's rendered prompt is a stored blob. A shell command longer
than 131,071 bytes — Linux's per-argument limit, which would otherwise fail `execve`
inside the container — and an agent prompt longer than 1 MiB are refused at render,
before anything is dispatched or stored: the stage fails `rendered_prompt_over_bound`,
naming the size and the bound. An agent's validation retry is checked again after its
feedback is appended. A `target.diff` is better read from `/work`'s git
history in a command than inlined into one.

## Stage wall-time bounds

`stage(timeout_ms = N)` is the per-stage wall-clock budget in milliseconds. A
stage that omits it — or passes `0`, which is the DSL's spelling for "unset" and
what the `workflows/std/kata/std.star` helpers forward by default — is given the
authoring default `kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS`, **one hour**,
in the frontend. So every checked stage carries a bound and none runs unbounded.
A declared positive value always wins; a NEGATIVE value is refused by name at
load. The resolved value is visible in the checked IR (`kata workflows inspect
--format json`) and folded into the stage `contract_hash`, so changing a stage's
declaration rotates its identity.

**A stage's own hashed `timeout_ms` is the ONLY wall clock.** There is no
node-level cap and no per-agent timeout key: an operator cannot raise or lower a
stage's budget from `kata.toml`, because a bound that is not in the program's
hash is a bound the program never agreed to.

## Authoring diagnostics

A stage id may not contain `#`: kata reserves it for the names it mints itself (a
`branch()` route's `#op/<path>`, and rows such as `<stage>#branch-skip`), and
`kata check` refuses such an id as `stage_id_reserved_character`.

A template reads `{{ stages.<producer>… }}` only from a stage it depends on, directly
or through other stages: `kata check` refuses a `{{ … }}` read of any other stage — a
sibling branch, a downstream stage, the stage itself — as
`output_reference_outside_dependency_closure`, and at run time a template's `stages.*`
holds only those upstream stages, so a read the check does not see (inside `{% … %}`,
or through a computed index) finds that stage absent on every schedule rather than on
some.

`kata check` collects DSL errors, prints the accepted surface, and exits 2 (`usage`),
the class every `check` face gives a workflow that does not compile. For example:

```console
$ kata check ./broken.star
Error: compiling ./broken.star

Caused by:
    0: failed to parse resolved workflow at ./broken.star
    1: validation error: kata workflow DSL: 2 definition errors found — fix all of them, then re-check:
         broken.star:1:5: ✗ stage() got an unknown keyword `model`; did you mean `model_hint`?
         broken.star:2:1: ✗ workflow() got an unknown keyword `stages`; did you mean `root`?
       accepted stage() keywords: agent, allowed_tools, approval, approval_reason, body, cache_policy, consumes, cost_budget, depends_on, execution_requirements, exit_policy, id, label, model_hint, op, output_bytes, outputs, produces, produces_files, progress_visibility, prompt, reads, required_capabilities, run, sandbox, timeout_ms, title, topology, validate_feedback_template, validate_retries, work_delta_bytes, work_delta_entries
       accepted workflow() keywords: bounds, cost_budget, description, external_input_channels, human_requests, max_concurrency, max_external_input_channels, max_human_requests, max_memory_selectors, max_memory_writebacks, memory_selectors, memory_writebacks, params, root, sandbox_profiles, tags, validation_criteria, version, workflow_pattern, worktree_isolated
         (plus the workflow name as the first positional argument: workflow("name", root=...))
```
