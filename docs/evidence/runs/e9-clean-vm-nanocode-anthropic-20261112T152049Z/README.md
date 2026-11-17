# kata

kata is a durable workflow engine for agentic software work. You write a
workflow in Starlark. kata checks it, compiles it to a content-hashed execution
program, and runs every shell command and coding-agent turn inside a rootless
OCI container, with a durable record of what each stage did.

**Status:** a pre-release prototype. There is no release yet: kata is built
from a source checkout. Linux x86-64 only; macOS and ARM64 are not supported.
Interfaces, configuration and on-disk formats change without migration. See
[What is proven today](#what-is-proven-today).

## Requirements

- Linux on x86-64
- Rust, through [rustup](https://rustup.rs/). The checkout's
  `rust-toolchain.toml` pins the release, and rustup installs it on the
  first build.
- A C compiler (`cc`), and `git` with your identity set (`user.name` and
  `user.email`): kata commits as you and never invents an identity, so
  `kata doctor` fails its `commit_identity` row without one.
- [Nix](https://nixos.org/download/), at runtime, with the `nix-command`
  feature enabled. kata's container runtime (a pinned youki) and the
  environments its containers see are Nix store paths; `kata host setup`
  builds or downloads them for you. The Nix install below also needs the
  `flakes` feature.
- cgroup v2, with a subtree delegated to your user that carries the `memory`
  and `pids` controllers. kata places each container's cgroup inside the
  delegated cgroup kata itself runs in, so start kata under
  `systemd-run --user --scope -p Delegate=yes` or through the unit
  `kata service install` writes; both need a systemd user session. The
  installed service does not read `.env`: `kata service install` captures the
  provider declaration `kata host setup` writes there, so re-run the install
  after re-running host setup.
- unprivileged user namespaces enabled
- AppArmor, and `sudo` once. `kata host setup` installs an exact-path AppArmor
  profile for kata's pinned youki runtime, through `sudo kata host
  apparmor-install`. On a kernel with
  `kernel.apparmor_restrict_unprivileged_userns=1`, Ubuntu's default, youki
  cannot create a user namespace without it.
- The GitHub CLI, `gh`, only for pull requests: a `--target pr:<N>` run reads
  the pull request with `gh pr view` and `gh repo view`, and a workflow with a
  `forge_export` stage (`change`, for one) opens its pull request with `gh pr
  create`. kata runs the `gh` on the main's `PATH` as `gh auth login` left it
  and carries no GitHub client or token of its own. Nothing else needs `gh`.

`kata host setup` checks each of these, except `gh`, by name and reports the
first one that is missing. kata needs no `sqlite3` program: SQLite is built
into it.

Ubuntu 24.04 Server as installed meets the kernel, cgroup, user-namespace and
AppArmor requirements (measured on Canonical's 24.04 server cloud image). In
bash, these commands install the rest (put your own name and email in the last
two):

```sh
sudo apt-get update
sudo apt-get install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --daemon --yes
mkdir -p ~/.config/nix ~/.local/bin ~/.local/state
chmod go-w ~/.config ~/.local ~/.local/state
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
git config --global user.name 'Your Name'
git config --global user.email 'you@example.com'
sudo apt-get install -y gh   # only for pull requests; then run `gh auth login` once
```

Then open a new terminal. The rustup and Nix installers put `cargo` and `nix`
on the `PATH` of new login shells, and Ubuntu's `~/.profile` adds
`~/.local/bin` once that directory exists.

## Install from source

Clone kata, build it, and put it on your `PATH`:

```sh
git clone https://github.com/N0xMare/kata
cd kata
cargo build --release --locked
cargo build --release --locked --target x86_64-unknown-linux-musl -p kata-toolhost
mkdir -p ~/.local/bin ~/.local/state
chmod go-w ~/.local ~/.local/state
ln -sf "$PWD/target/release/kata" "$PWD/target/release/kata-worker" ~/.local/bin/
~/.local/bin/kata --version
```

The steps below run `kata` by name, so `~/.local/bin` must be on your `PATH`.
On Ubuntu a new terminal puts it there once the directory exists; elsewhere,
add it yourself.

The `chmod` lines matter where new directories are group-writable, as under
Ubuntu's default umask (`002`), or where other software created
`~/.local/state` first. kata publishes under directories of yours (the main's
address under `~/.local/state/kata`; the unit `kata service install` writes
under `~/.config/systemd/user`, and its environment snapshot under
`~/.config/kata/service-environments`) and refuses to while any directory of
yours on that path is writable by anyone else: `kata serve` stops with `could
not publish verified client discovery`, names the directory, and ends with the
command that fixes it (`fix: chmod go-w <directory>`). A directory another
account owns is refused with the reason and no command. The Ubuntu block above
also clears `~/.config`, which `kata service install` needs; `kata login`
checks only its own `~/.config/kata/logins` directory, which it creates mode
0700.

`cargo build --release` builds exactly the four shipped binaries into
`target/release/`: `kata`, `kata-worker`, and the container provider's
`kata-provider-youki` and `kata-oci-hook`. The second build makes the fifth,
`kata-toolhost`, the init of a nanocode agent container, static for
`x86_64-unknown-linux-musl` (a container's root filesystem has no dynamic
loader), into `target/x86_64-unknown-linux-musl/release/`; rustup installs
the target from `rust-toolchain.toml`. Link `kata` and `kata-worker`
onto your `PATH` (`~/.local/bin` above), rather than copying them: kata
resolves its own path, so the linked binary finds the standard workflow
library, the provider binaries and the checkout's Nix expressions in the
checkout. A copied binary, or one installed with `cargo install`, finds none
of them. The build must land in the checkout's own `target/`, so unset
`CARGO_TARGET_DIR` if you set it. With [just](https://github.com/casey/just)
installed, `just install` runs the same two builds and links.

Rebuilding `target/release` changes what the links run. The provider binaries
`kata host setup` provisioned are copies, so after a rebuild (for example after
a `git pull`), re-run `kata host setup` in each project: it provisions the new
provider binaries and updates the exports it wrote to `.env`. If you use the
installed service, re-run `kata service install` too.

### Alternative: install with Nix

```sh
nix profile install github:N0xMare/kata
```

The package carries the same binaries plus its own copy of the workflow
library and the files `kata host setup` reads. The flake names kata's binary
cache, `katacode.cachix.org`. Whether Nix uses it depends on your Nix
configuration (`accept-flake-config`, trusted users); without it, Nix builds
kata from source.

## Quickstart

At the root of a git repository, create the project config and prepare the
host:

```sh
kata init
systemd-run --user --scope -p Delegate=yes -- kata host setup --install-apparmor
```

`kata init` writes `.kata/kata.toml`, starter workflows under
`.kata/workflows/`, and ignore rules in `.gitignore`. `kata host setup` runs
the host checks, realises the pinned youki, installs its AppArmor profile
through `sudo` when it is missing or differs, provisions kata's container
provider, declares the default capsule environment in `.kata/kata.toml`, and
finishes with `kata doctor`. Run from a source build, it provisions the
provider binaries built beside `kata`, and builds the pinned youki (when it is
not already in the Nix store) and the default environment with `nix-build`
from the checkout's `nix/` directory, rooting each under `.kata/nix-roots`.
The first run can take several minutes while Nix downloads or builds them;
Nix's build log streams to the terminal as it runs.
The `systemd-run` prefix starts kata in a cgroup delegated to your user. From
an SSH or console login shell, which is not delegated, `kata host setup`
refuses at its `cgroup_v2` step and `kata serve` refuses to boot.

Start the main in one terminal and run the starter workflow in another:

```sh
systemd-run --user --scope -p Delegate=yes -- kata serve --config .kata/kata.toml   # terminal 1
kata run std.hello --wait --timeout-secs 60                                          # terminal 2
```

`std.hello` is one shell stage that `kata init` writes into
`.kata/workflows/`. It needs no model or API key. `kata check std.hello` checks
it without running it, and `kata workflows list` shows every workflow kata can
find.

For a longer walk-through, including writing your own workflow, see
[docs/getting-started.md](docs/getting-started.md).

## What is proven today

- **One agent harness.** nanocode, embedded in the worker, is the only agent
  kata ships (`nanocode_openai`, `nanocode_anthropic`). Its model calls leave
  from the worker; its tool calls run in the stage's rootless container. The
  vendor coding-agent CLIs kata once ran as measurement baselines (Codex,
  Claude Code through claude-agent-acp, Grok, pi, opencode) are removed; their
  counted-round records below stay as measured. `just live-nanocode` runs the
  harness's live acceptance; it spends real model budget.
- **The engine, model-free.** Admission, durable records, recovery by replay,
  loops, approval gates, workspace effects and containment are covered by the
  test suite and the model-free live smokes, with scripted agents standing in
  for real models.
- **The `change` and `review` packs, end to end.** `workflows/std/change.star`
  (task text -> plan -> implement -> test fix loop -> human approval -> commit,
  land, PR) and `workflows/std/review.star` (`--target pr:<N>` or the trunk head
  -> find -> verify -> a typed review) ran on real models in the counted round
  below. In the L1 containment lane both run end to end in real containers on
  the embedded harness against a scripted mock model, beside the agent pack and
  its checked-command twin.
- **Both packs, on real models: the counted round.** At commit `34d5c77c8ff7`,
  the embedded harness on `nanocode_openai` (`gpt-6-luna`, through kata's own
  ChatGPT login) and two vendor baselines, codex (`codex-stock`) and Claude Code
  through `claude-agent-acp`, each ran `review` three times on a pull request
  with seeded defects and three times on one real third-party public pull
  request, `change` three times to a delivered pull request, and once a variant
  of `change` whose fix loop must refine a failed first attempt on a held-out
  gate's feedback. The 30 run records, none void, each outcome read outside kata
  (git, the forge, a read-only database handle), are on the
  [evidence page](docs/evidence/README.md), which renders both parity verdicts
  from them:
  - OpenAI parity: not met — nanocode-openai passes fewer counted runs than codex-stock: E1 seeded-pr.
  - Anthropic parity: not met — fewer than 3 counted runs: nanocode-anthropic E1 seeded-pr; nanocode-anthropic E1 public-pr; nanocode-anthropic E2 pr.
- **Not done yet.** `nanocode_anthropic` on a real model: 0.0.1 ships it
  untested-live, with no counted run and its funded acceptance cells
  (`just live-nanocode`) owed. It runs against mock model providers in real
  containers. At the round's commit the provider refused its one funded turn
  before any output, which kata recorded as refused, PROVEN NOT PERFORMED:

  `HTTP 400 invalid_request_error: Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits.`

  Also not done: a crash in the middle of a real model call, proven live (an
  interrupted attempt settles PROVEN AMBIGUOUS and fails the stage; kata never
  re-runs it); an install proven on a clean machine.

## How it works

`kata serve` runs the **main**: the one process that holds the durable state of
every run. It admits workflows, records each step, and recovers runs after a
restart. **Workers** execute stages for the main, always as separate
`kata-worker` processes: `kata serve` starts and supervises one (the node `kata
init` configures, `type = "supervised_node"`), and the main hosts none. Each stage runs in a **capsule**: a rootless
OCI container started by a pinned, seccomp-enabled build of
[youki](https://github.com/youki-dev/youki). A capsule sees only the Nix
closure the node declares, its declared view of the workspace, and the network
access the stage declares. A **workflow** is a Starlark file that declares
stages, their typed outputs, and how they connect: dependencies, `parallel()`,
`branch()`, loops, approval gates and durable waits. kata checks the whole
graph before anything runs.

## Agents and credentials

kata's one agent harness is nanocode, embedded in the worker: `kata init` declares
it as the default agent, and again as the `reviewer` and `gate` role agents that
shipped packs select where they split work (point either at another model by
editing its block). It runs the agent loop in the worker (`adapter =
"nanocode_openai"` for OpenAI's Responses API, `"nanocode_anthropic"` for
Anthropic's Messages API); a block naming any other adapter is refused
`adapter_unqualified` by `kata config check`, `kata doctor` and the check of every
stage that selects it.

Each agent declares its credential in the node config as a reference, never as
the secret itself:

- **kata's own login.** `kata login openai` (a ChatGPT login) or `kata login
  openai --api-key < key-file` writes an owner-only file under
  `~/.config/kata/logins/`, which kata refreshes itself. kata never reads another
  tool's login. `kata init` writes this block:

  ```toml
  [agents.default]
  type = "codex"
  adapter = "nanocode_openai"
  model = "gpt-6-luna"
  reasoning_effort = "medium"
  credential = { mode = "subscription", source = "kata_login" }
  ```

  Use `mode = "api_key"` after `kata login openai --api-key`.
  `nanocode_anthropic` takes `mode = "api_key"` only (`kata login anthropic
  --api-key`, or `source = "env:ANTHROPIC_API_KEY"`).

- **API key in the environment.** The worker reads the key from an environment
  variable on the host:

  ```toml
  [agents.default]
  type = "codex"
  adapter = "nanocode_openai"
  credential = { mode = "api_key", source = "env:OPENAI_API_KEY" }
  ```

You are responsible for using each provider's account and subscription in line
with that provider's terms. kata does not check them for you.

The [operator guide](docs/product/operator-guide.md) covers models, reasoning
effort and credential refresh in detail.

## Documentation

- [Getting started](docs/getting-started.md): install, first run, first
  workflow
- [Operator guide](docs/product/operator-guide.md): host preparation,
  configuration, running and observing workflows
- [Architecture](docs/architecture/0001-replacement-architecture.md): the
  design and the properties it protects
- [ADR 0002: Effect permits](docs/architecture/0002-effect-permits.md)
  (Proposed): per-effect permits at the main's effect doors, planned after 0.0.1
- [ADR 0003: Process topology](docs/architecture/0003-process-topology.md)
  (Proposed): kata's process topology after 0.0.1, its control plane, model
  gateway, effects worker and execution nodes
- [Documentation index](docs/README.md): every other document, including the
  contributor material
- [Changelog](CHANGELOG.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev shell, the test runner and
the checks a change must pass.

## Security

kata is a containment product. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not open a public issue.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party notices are in [NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution you intentionally
submit for inclusion in kata, as defined in the Apache-2.0 license, is dual
licensed as above, without any additional terms or conditions.
