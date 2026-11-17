# Feasibility probes

`just feasibility-probes` runs `scripts/feasibility-probes.py` and prints the current
host's capability matrix as a table (`--json` for machine-readable rows, `--only <group>`
to run one group: `youki`, `nix`, `artifact`). It spends no model tokens. It exits
non-zero when any row is `failed`.

Each row has one of four statuses:

- **passed:** this narrow probe observed its named behaviour;
- **failed:** an available prerequisite disagreed with the probe contract;
- **unsupported:** the prerequisite is absent on this host; and
- **not_run:** the prerequisite may exist, but the experiment or adapter it would
  exercise is not implemented.

An absent prerequisite is never reported as a pass.

| Group | What it observes |
|---|---|
| `artifact` | A portable byte artifact survives relocation, and corruption is detected. |
| `nix` | The local Nix store: add-path, closure, integrity and an indirect GC root. |
| `youki` | The pinned youki named by `config/youki-pin.toml`, resolved by its exact store path (never `$PATH`): its version floor, its sha256, that it was built with libseccomp, and that it runs a rootless `/bin/true` container to exit 0 in a delegated systemd user scope. |

A passed probe is not qualification. A production claim also needs the crate suites
and the live smokes that `docs/development/verification.md` routes.
