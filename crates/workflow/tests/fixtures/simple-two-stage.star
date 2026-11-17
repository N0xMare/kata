# simple-two-stage — implement then test. Exercises a two-stage linear DAG
# through the orchestrator; the `worker` agent label is backed by a mock
# backend in tests.

implement = stage(id = "implement", agent = "worker", prompt = "implement it")
test = stage(id = "test", depends_on = ["implement"], run = "echo test passed")

workflow(
    "simple-two-stage",
    description = "Implement then test",
    root = [implement],
)
