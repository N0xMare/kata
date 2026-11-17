# kata documentation

## Start here

| Document | For |
|---|---|
| [Getting started](getting-started.md) | Install kata, run a shipped example, write your first workflow. |
| [Operator guide](product/operator-guide.md) | Running kata: host preparation, `kata host setup`, the `oci` engine, agents and credentials, caches, approvals, cancelling, run output, upgrades. |
| [Architecture](architecture/0001-replacement-architecture.md) | How kata is designed, and the properties the design protects. |
| [Evidence](evidence/README.md) | The real-model runs kata's claims rest on (review, change, crash and restart, clean machine), each with its record and artifacts, or "not yet run". |

Outside this directory:

- [README](../README.md): what kata is, requirements, quickstart
- [workflows/examples](../workflows/examples/README.md): the example workflows,
  each with a header that says what it demonstrates and how to run it
- [CHANGELOG](../CHANGELOG.md)
- [CONTRIBUTING](../CONTRIBUTING.md) and [SECURITY](../SECURITY.md)

## For contributors

These describe how kata is developed and tested. You do not need them to use
kata. Start with [CONTRIBUTING](../CONTRIBUTING.md) and
[AGENTS.md](../AGENTS.md), the working agreements for human and coding-agent
contributors.

| Document | Contents |
|---|---|
| [development/verification.md](development/verification.md) | Which checks a change needs. Its routing table is read by `just verify`, so keep its format. |
| [development/evaluation.md](development/evaluation.md) | The `kata-eval` task harness behind `just eval` and `just eval-live`. |
| [development/nanocode.md](development/nanocode.md) | How kata pins nanocode, the vendored Code Mode engine and its patch, and the check that keeps the copy exact. |
| [development/feasibility-probes.md](development/feasibility-probes.md) | What `just feasibility-probes` reports, and what each result means. |
| [architecture/0002-effect-permits.md](architecture/0002-effect-permits.md) | Proposed: per-effect permits at the main's effect doors, planned after 0.0.1; implemented so far for the forge export's push and pull request (ADR 0003's stage E1). |
| [architecture/0003-process-topology.md](architecture/0003-process-topology.md) | Proposed: kata's process topology after 0.0.1 — control plane, model gateway, effects worker and execution nodes, what each holds and refuses, and the links between them. |
| [architecture/0004-mcp-workstation-local-forms.md](architecture/0004-mcp-workstation-local-forms.md) | Accepted: the closed list of workstation-local forms `kata mcp` serves outside its principal, the HTTP API, and the check that refuses any other form within its stated bounds. |
| [architecture/protected-properties.md](architecture/protected-properties.md) | The properties the engine must preserve and the constructs it ships, each with how it runs. |
| [architecture/protected-properties.toml](architecture/protected-properties.toml) | The machine-read ledger mapping each property, construct and crash boundary to the tests that prove it. A test checks it against the document above on every `just test`. |
