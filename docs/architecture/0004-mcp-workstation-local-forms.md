# ADR 0004: MCP's workstation-local forms

- Status: Accepted (by the owner, 2026-11-13)
- Date: 2026-11-13
- Scope: what `kata mcp` may serve outside its principal, the HTTP API, and the check
  that refuses any other form within the bounds stated under "Bounds"
- Amends: `AGENTS.md`, "Four principal surfaces, and two derived ones"

## Context

kata has four principal surfaces (the Starlark frontend, the `kata` CLI, the API server,
the Rust SDK) and two derived ones: MCP derives from the API, and the installed skill
derives from the CLI. Until this ADR, the rule was that a derived surface "may expose a
SUBSET of its principal and may never advertise what its principal lacks".

The default `kata mcp` attaches to the installed main and proxies each operation to the
API's `POST /api/v1/ops/{operation}` route (`kata::cli::mcp::remote_invoke`). Some of
what an authoring agent needs reads the CALLER's workstation, which the main cannot do:
the main and its node may run on another machine, and neither can read a client's files
or list a client's library. `kata mcp` therefore serves those forms itself, through the
same code the CLI runs (`kata::cli::mcp::tools::invoke`), on every binding:

- the `author` tool, which scaffolds a project-local config and workflow library (the
  API's `/ops/author` answers `usage`, "a workstation-local operation");
- `check` with `all = true`, the caller's effective library (the API refuses it
  `usage`, "a workstation-local operation");
- `check` of a `.star` path, the caller's own file (the API resolves `workflow` only as
  a library name, so it answers a path `not_found`);
- the resource `kata://workflows/dsl-catalog`, the document `kata workflows schema`
  prints (the API has no resource routes).

## Problem

L3 finding R4-01: the rule and the code disagreed. MCP advertised and served those four
forms while its declared principal served none of them, so "may never advertise what its
principal lacks" was false. Finding R4-02: the derivation guard stayed green because it
took "what the API serves" from the contract enum (`Operation::ALL`, `descriptors()`),
which `tools/list` is built from too, and no guard covered MCP resources.

Either the surface changes or the rule does. Removing the forms leaves an agent unable to
scaffold, check its own files or read the DSL schema without leaving MCP for the CLI.
Serving them from the API cannot work: the API runs where the main runs.

## Decision

1. **The rule is amended, not the surface.** MCP derives from the HTTP API PLUS a closed,
   test-pinned list of workstation-local forms. Each form acts only on the caller's own
   files, through the CLI's code. `AGENTS.md` now reads: "A derived surface may expose a
   SUBSET of its principal and may never advertise what its principal lacks — save
   MCP's pinned workstation-local forms (`author`, `check` of local files, the DSL
   catalog), which act only on the caller's own files through the CLI's code".

2. **The list is closed.** It is exactly these four entries, the rows of
   `MCP_SERVED_OUTSIDE_THE_API` in `bin/kata/tests/surface_inventory.rs`, pinned by
   `MCP_SERVED_OUTSIDE_THE_API_COUNT = 4`:

   | kind | entry | the CLI's twin |
   |---|---|---|
   | tool | `author` | `kata init` |
   | form | `check` with `all = true` | `kata check --all` |
   | form | `check` whose `workflow` is a `.star` path | `kata check <path>` |
   | resource | `kata://workflows/dsl-catalog` | `kata workflows schema` |

   Adding a form means a new ADR or an amendment to this one, plus the row and the count
   in the same change.

3. **The refused set.** Anything else MCP serves outside the API is refused, within the
   bounds stated under "Bounds":
   - a tool whose operation the API, asked through its own router, answers with its
     not-served refusal, unless a `tool` row names it (R7);
   - any resource that no `resource` row names, because the API serves no resources
     (R8);
   - a call that the default (attached) `kata mcp` answers with a success while sending
     no request to the API, unless a row matches the call (R10).

   A row that is no longer true is refused too (R9): its API probe is now answered `ok`,
   the attached `kata mcp` no longer serves its form at the caller, or its resource is
   no longer advertised. A count other than the pinned one is refused as well.

4. **The mechanism asks the API, not kata's own table.**
   - `surface_inventory::mcp_advertises_no_tool_the_api_does_not_serve` covers R7, R8
     and the probe and resource halves of R9. It builds a real `ApiServer` router over a
     booted engine (`probe_api_router`) and POSTs each operation to
     `/api/v1/ops/{operation}` (`api_served_operations`, `api_ops_answers`). An answer
     carrying the API's not-served refusal means the API does not serve that operation.
     The same function still holds R1 to R4, which read the contract.
   - `surface_inventory::the_attached_mcp_serves_at_the_caller_only_its_pinned_forms`
     covers R10 and the form half of R9. It runs the real `kata mcp --connect` against
     that router on loopback, with a layer in front of the router that records every
     request it receives (`drive_attached_forms`). It calls every advertised tool with a
     corpus generated from the tool's own `inputSchema` (`generated_form_corpus`,
     `sample_values`), placing an `observe` marker between calls so each call's requests
     can be told apart. A call that answered `ok` with no request between its markers
     was served at the caller. What reached the API is read from the API side, never
     from MCP's own routing (`check_reads_the_workstation`).
   - `surface_inventory::sugar_may_be_a_strict_subset_of_its_principal` pins the other
     direction. The tools MCP advertises that the API does not serve, measured the same
     way, are exactly `author`.

   The refusal was watched to fail first. With only three rows pinned, R10 named the one
   unpinned form, `check {"workflow":"<tmp>/derivation-probe.star"}`. With `check
   all = true` mutated to proxy, R9 named the `check all=true` row as stale. With every
   `check` served at the caller (`check_reads_the_workstation` answering yes), R10 named
   `check {"workflow":"kata-loop-lite"}`, a library name served outside the API.

## Bounds

Stated so that the check claims no more than it refuses:

- **R10 is bounded by its corpus.** For each tool it sends a base call with every
  required property, then the base with one property at a time set to each sample:
  both booleans, `1`, `[]`, `{}`, and for a string a name no library holds, a name the
  caller's library resolves (`kata-loop-lite`, from the shipped standard library) and
  the path of an existing `.star` file. A form served at the caller only for some other
  value, or only for a combination of two optional properties, is not refused.
- **R8 reads `resources/list` only,** off a `kata mcp --no-engine` (the resources a
  server lists do not depend on its binding). A resource is refused when the listing
  names it and no row does. A `resources/read` of a URI the listing does not name, and
  any JSON-RPC method other than `tools/list`, `tools/call` and `resources/list`, are
  not probed, so a form served there is not refused.
- **A refusal at the caller serves nothing.** A call that `kata mcp` refuses without
  reaching the API (bad arguments, a path naming no file) is not refused.
- **`kata mcp --no-engine` attaches to no API.** It serves the pinned forms and also
  `check` by library name against the caller's library, which is `kata check NAME`'s own
  resolution. No guard refuses that, because that binding has no principal to derive
  from. The rule governs the default, attached binding.
- **A `run` of a `.star` path is not outside the API.** MCP reads the file and submits
  it as the inline `workflow_starlark` that the API serves, and R10 sees that request
  reach the API.

## Consequences

- The installed skill's rule is unchanged: it derives from the CLI and from what MCP
  advertises (R5, R6). The skill teaches `author`, the path and `all` forms of `check`,
  and the catalog resource, all of which MCP now serves within its amended rule.
- A form joins MCP outside the API only through this ADR's list: the guard reds on an
  unpinned one, and on a pinned one that stopped being true.

## Alternatives considered

- **Drop the four forms from MCP.** Rejected. An agent with only the MCP surface could
  no longer run the authoring loop (author, check, run, observe) on its own files.
- **Serve them from the API.** Rejected. The API runs where the main runs, and from
  there it can read neither the caller's files nor the caller's library.
- **Name the CLI as MCP's second principal outright.** Rejected. That would let MCP
  serve anything the CLI does, and no check could say which forms were meant. The
  closed list keeps the exception the size of the need.
