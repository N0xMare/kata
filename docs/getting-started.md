# Getting started

This page takes you from nothing to running a workflow you wrote yourself. It
needs no model and no API key: every stage here is a shell stage.

You need Linux on x86-64, Rust through rustup, a C compiler, git with your
identity (`user.name`, `user.email`) set, Nix (with the `nix-command`
feature), cgroup v2 with a systemd user session,
unprivileged user namespaces, and AppArmor; pull requests (a `pr:<N>` target,
a `forge_export` stage) also need the GitHub CLI, `gh`, logged in. See the
[README](../README.md#requirements) for details, and for the commands that
install them on Ubuntu 24.04.

## 1. Install kata

kata is built from a source checkout:

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

The first build produces the `kata` and `kata-worker` binaries and kata's
container provider (`kata-provider-youki`, `kata-oci-hook`) in
`target/release/`; the second, the static `kata-toolhost` a nanocode agent
container runs as its init, in `target/x86_64-unknown-linux-musl/release/`. The
`chmod` keeps `~/.local` and `~/.local/state` writable by you alone, which the
main requires of every directory of yours on the path it publishes its address
under (Ubuntu's default umask leaves new directories group-writable). A
`could not publish` refusal names any other such directory and ends with the
command that fixes it (`fix: chmod go-w <directory>`). The
steps below run `kata` by name, so `~/.local/bin` must be on your `PATH`: on
Ubuntu a new terminal puts it there once the directory exists. The links keep `kata` a build of this
checkout, so it finds the standard workflow library and, in the next step,
the provider binaries and the checkout's Nix expressions. Do not copy the
binary elsewhere or install it with `cargo install`: a copy finds none of
them. For the same reason the build must land in the checkout's own
`target/`: unset `CARGO_TARGET_DIR` if you set it. If you have
[just](https://github.com/casey/just), `just install` does the same builds and
links.

To install with Nix instead, run `nix profile install github:N0xMare/kata`
(this needs Nix's `flakes` feature too). That package carries its own copy of
the workflow library and of the files `kata host setup` reads.

## 2. Create a project and prepare the host

Run these at the root of the git repository you want kata to work in:

```sh
kata init
systemd-run --user --scope -p Delegate=yes -- kata host setup --install-apparmor
```

`kata init` writes `.kata/kata.toml`, a few starter workflows under
`.kata/workflows/` (including `std.hello`), and adds the paths kata
writes to `.gitignore`. It then prints suggested next commands.

`kata host setup` runs these steps by name, and stops at the first one that
refuses:

- `platform`, `nix`, `cgroup_v2`, `userns`: the host checks. `nix` runs
  `nix store info`, the call the main makes at boot, so it requires the
  `nix-command` feature and a running Nix daemon. `cgroup_v2`
  requires a cgroup delegated to your user with the `memory` and `pids`
  controllers usable. `userns` requires unprivileged user namespaces.
- `youki`: realises the pinned youki runtime from Nix and checks its sha256.
  From a source build, a youki missing from the Nix store is built with
  `nix-build` from the checkout's `nix/youki.nix`; Nix downloads it instead
  when a binary cache you use has it.
- `apparmor`: checks the runtime's exact-path AppArmor profile. Only root can
  read the kernel's list of loaded profiles, so when the installed profile
  matches, the step starts one rootless container of the pinned runtime and
  reports the profile in place when it starts; such a run, with or without
  the flag, installs nothing. When the profile is missing or differs, or
  AppArmor refuses that container, `--install-apparmor` runs `sudo kata host
  apparmor-install` to install it; without the flag the step prints that
  command for you to run and the run reports `status: incomplete`.
- `provider`, `env_file`, `config`: provisions kata's container provider, with
  the iproute2 `ip` its network hook runs, under `.kata/providers`, writes its
  three `KATA_EXTERNAL_*` settings to `.env`, and declares the default capsule
  environment in `.kata/kata.toml`. From a source build, the provider binaries
  are the ones beside `kata` in `target/release/`, and `ip` and the default
  environment come from one `nix-build` of the checkout's `nix/share.nix`,
  rooted at `.kata/nix-roots/kata-share`; Nix's build log streams to the
  terminal. After you rebuild kata, re-run `kata host setup`: it provisions
  the rebuilt provider binaries and updates the settings it wrote to `.env`.
- `doctor`: runs `kata doctor`. The run reports `status: complete` only when
  every required check passes and no action is left for you.

The `systemd-run` prefix runs kata in a fresh scope that your systemd user
manager delegates to you. kata needs that: from an SSH or console login shell,
which sits in a session scope that is not delegated, the `cgroup_v2` step
refuses with `delegation_incomplete` and names the remedy. On hosts without
AppArmor the `apparmor` step cannot complete.

You can re-check the project at any time:

```sh
systemd-run --user --scope -p Delegate=yes -- kata doctor --config .kata/kata.toml
```

`kata doctor` exits non-zero only on a `fail`. Its `containment_*` rows report
the pinned runtime, the user-namespace and AppArmor state, the seccomp filter
and the cgroup delegation of the process it runs in. Without the
`systemd-run` prefix, `containment_cgroup_delegation` warns about your shell,
not about the main you will start.

## 3. Start the main

The main is the one long-running kata process. Start it in its own terminal,
from the project root, and leave it running:

```sh
systemd-run --user --scope -p Delegate=yes -- kata serve --config .kata/kata.toml
```

Started from a shell that is not delegated, `kata serve` refuses to boot with
`oci_route_uncertified` (`delegation_incomplete`). To run the main as a
systemd user service instead, see `kata service install --help`; the unit it
writes sets `Delegate=yes`.

The other commands on this page talk to the main over HTTP at
`http://127.0.0.1:8400` (the `[api] bind` in `.kata/kata.toml`). Set
`--api-url` or `KATA_API_URL` to use another address.

## 4. Run the starter workflow

`std.hello` is the smallest workflow: one shell stage that prints a JSON
object. `kata init` wrote it, so it needs no installed library. From the
project root:

```sh
kata check std.hello
kata run std.hello --wait --timeout-secs 60
```

`kata check` compiles the workflow and runs the verifier without executing
anything. `kata run --wait` submits the workflow to the main and waits for it
to finish. Stage `hello` completes, and its parsed output is
`{"greeting": "hello from kata"}`.

To look at the result again later:

```sh
kata run list
kata run output <execution-id>
kata run output <execution-id> hello
```

`kata workflows list` prints every workflow name kata can resolve, and the
directories it searched.

## 5. Write your own workflow

A workflow is a Starlark file. It declares stages with `stage(...)`, then
calls `workflow(...)` once with the workflow's name and its stages. Save this
as `.kata/workflows/my-first-workflow.star`:

```python
# Two shell stages. `reply` runs after `greet` and reads its typed output.

greet = stage(
    id = "greet",
    run = """
printf '{"name":"kata"}\\n'
""",
    agent = "shell",
    outputs = {
        "name": "string",
    },
    progress_visibility = "summary",
)

reply = stage(
    id = "reply",
    depends_on = ["greet"],
    run = """
printf '{"message":"hello, %s","ok":true}\\n' '{{ stages.greet.parsed.name }}'
""",
    agent = "shell",
    outputs = {
        "message": "string",
        "ok": "bool",
    },
    progress_visibility = "summary",
)

workflow(
    "my-first-workflow",
    description = "Two shell stages; the second renders the first's output.",
    root = [greet, reply],
)
```

What each part does:

- `agent = "shell"` runs `run` as a shell command inside a rootless
  container. By default the stage may land no change to the workspace and
  has no network. The workspace is still writable inside the container while
  the command runs: a stage that leaves a change there fails
  (`work_delta_out_of_scope`) and nothing of it is applied. An untracked
  file the repository's `.gitignore` ignores (a build's `target/`) is not a
  change here: it is discarded, and the stage does not fail.
- `outputs` declares the stage's output fields and their types. The stage
  prints one JSON object with those fields on stdout, and kata checks it
  against the declaration.
- `depends_on = ["greet"]` orders `reply` after `greet`. Inside `run`,
  `{{ stages.greet.parsed.name }}` is replaced with `greet`'s `name` output.
- `progress_visibility = "summary"` lets the event stream carry a short
  preview of the stage's progress. The default, `"off"`, carries none.
- `workflow(...)` takes the name positionally and the stages as `root = [..]`.
  `kata check` refuses `stages =`.

Check it, then run it:

```sh
kata check my-first-workflow
kata run my-first-workflow --wait --timeout-secs 60
kata run output <execution-id> reply
```

`reply`'s output is `{"message": "hello, kata", "ok": true}`.

A workflow in `.kata/workflows/` resolves by its name. `kata check` resolves
the name in the directory you run it from; `kata run` sends the name to the
main, which resolves it against the directory it was started in (step 3 starts
it from the project root, so here the two agree) and its own
`~/.kata/workflows/`. From anywhere else, pass a path, which `kata run` reads
and submits: `kata run .kata/workflows/my-first-workflow.star --wait`. A
project workflow takes priority over one with the same name in
`~/.kata/workflows/`, in the bundled standard library, or in the examples.

## Where to go next

The examples in [`workflows/examples`](../workflows/examples/README.md) are
installed with kata and resolve by name. Each opens with a header that says
what it demonstrates and how to run it. These need no model:

- [`fanout-merge.star`](../workflows/examples/fanout-merge.star): run stages
  in parallel with `parallel(...)` and join them with `sequence(...)`. Its
  branches write to the workspace, so they declare
  `sandbox = sandbox_profile(workspace = "rw")`.
- [`branch-routing.star`](../workflows/examples/branch-routing.star): route
  on a typed verdict with `branch()`.
- [`human-gate-approval.star`](../workflows/examples/human-gate-approval.star):
  a stage with `approval = True` waits for `kata run approve`.
- [`durable-wait-signal.star`](../workflows/examples/durable-wait-signal.star):
  park a run until someone answers a `human_request`.

The standard library, `kata/std.star`, has helpers you can `load`, for
example:

```python
load("kata/std.star", "shell_json_stage")

count = shell_json_stage(
    id = "count",
    run = "printf '{\"ok\":true}\\n'",
    outputs = {"ok": "bool"},
    reads = "whole-tree",
)
```

`shell_json_stage` builds a shell stage that starts with `set -eu` and sets
`progress_visibility = "summary"`. Its `reads` argument is required: a list of
repository-relative globs, or `"whole-tree"`.

To run coding agents as stages, give the agent its credential: `kata init`'s
default agent is the embedded nanocode harness, which needs only `kata login openai`
(or another `credential` in its block). The
[README](../README.md#agents-and-credentials) and the
[operator guide](product/operator-guide.md) cover the credentials. Model-backed
examples such as `code-review-loop.star` spend real model budget.
