# Local resource budget

- Reuse the existing two-node OVN-Light demo for local integration work. Inspect
  Docker/KIND inventory and available RAM before starting local workloads.
- Do not start additional local clusters or more than two demo nodes without an
  explicit user request. Leave unrelated clusters untouched.
- Use synthetic fixtures for large-cluster tests. Run the integration matrix on
  GitHub-hosted runners, not concurrently on the workstation.
- Keep local demo nodes capped at 4 GiB each, with no extra container swap. Use
  `scripts/local-kind-budget.py limit CLUSTER` before local deployment. A new
  local cluster needs 12 GiB available and no existing KIND nodes, including
  stopped ones. Do not delete existing clusters to make that check pass.
- Keep local builds at two Go workers (`GOMAXPROCS=2`, `GOFLAGS=-p=2`).
