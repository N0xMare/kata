# Evaluation

The `kata-eval` application is in `bin/kata-eval`; task definitions and validators
are test inputs in `test/eval/tasks`. `just eval` runs the deterministic mock tier and
must remain free of model spend. `just eval-live` drives the same task contract
through a configured provider under its explicit cap. Reports are generated output,
not tracked history; direct them to an ignored or temporary location.

Each task owns `task.toml`, a workflow, fixture/solution inputs where needed, and an
executable validator. Validators must inspect resulting filesystem behavior rather
than trust the engine's own status report.
