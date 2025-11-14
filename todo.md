# Foghorn TODO

This file tracks a multi-step improvement plan for Foghorn (architecture, correctness, performance, tests, and tooling). It is intended for iterative work; items can be checked off, split, or reprioritized over time.

## 1. Bootstrap and repository walkthrough

- Skim `README.md`, `README-DEV.md`, and `WARP.md` to align on intended behavior and dev workflow.
- Map modules and responsibilities: `src/foghorn/{main.py, app.py, server.py, transports/, plugins/, cache.py, stats.py, webserver.py, dnssec_validate.py}`.
- Grep for hotspots and known issues:
  - `git --no-pager log --oneline -n 50`
  - `git --no-pager grep -n --color 'TODO\|FIXME\|HACK\|XXX'`
  - `git --no-pager grep -n --color 'whitelist\|blacklist'`
  - `git --no-pager grep -n --color 'AD bit\|DNSSEC\|EDNS\|TC bit'`

## 2. Environment setup using `venv` and editable install

- Create and activate the project virtualenv:
  - `python3 -m venv venv`
  - `source venv/bin/activate`
  - `python -m pip install --upgrade pip`
  - `pip install -e '.[dev]'`
- Verify entrypoint:
  - `foghorn --help`
- Confirm useful Make targets (non-destructive ones):
  - `make build`
  - `make workflow-diagrams`

## 3. Run tests and capture coverage baseline

- Execute full suite:
  - `pytest --cov=foghorn tests`
- Generate and inspect coverage artifacts:
  - `coverage xml`
  - `coverage report -m`
- Note slowest tests and any failures for triage.

## 4. Static analysis and formatting pass

- Install linters and type tools into `venv`:
  - `pip install ruff mypy bandit pip-audit types-requests types-PyYAML types-lxml`
- Run format and lint checks:
  - `black --check src tests`
  - `ruff check src tests`
- Record findings; decide which rules to auto-fix vs. defer.

## 5. Type checking bootstrap

- Add a minimal `mypy.ini` with relaxed defaults (e.g. `ignore_missing_imports = True`).
- Run:
  - `mypy src/foghorn`
- Identify high-value modules to annotate first: `server.py`, `main.py`, `transports/*`, `plugins/base.py`.
- Plan incremental adoption; add `Protocol`/`TypedDict` types for configs and plugin interfaces.

## 6. Security and dependency audit

- Run static security scan:
  - `bandit -q -r src/foghorn`
- Audit dependencies:
  - `pip-audit`
- Manually review:
  - TLS defaults and verification in `transports/dot.py` and `transports/doh.py`.
  - Any usage of `eval`/`exec` or unsafe YAML (ensure `yaml.safe_load` everywhere).
  - Logging of sensitive data (client IPs, query names, headers).

## 7. Core request pipeline and correctness

- Deep dive into `server.py`: `DNSUDPHandler`, `resolve_query_bytes`, `compute_effective_ttl`, failover logic.
- Validate behavior against RFCs:
  - Negative caching (RFC 2308) for NXDOMAIN/NODATA.
  - TTL selection across records (min TTL across relevant sections) and consistency with `min_cache_ttl` docs.
  - TC bit fallback: retry same upstream via TCP before failing over to others.
  - EDNS(0) OPT record handling and UDP payload size (e.g., 1232 default).
  - DO/CD/AD bit semantics across DNSSEC modes (`ignore`, `passthrough`, `validate` with `upstream_ad` vs `local`).
- Identify thread-safety risks in class-level state during reloads and concurrent requests.

## 8. Transports and connection management

- Evaluate `udp.py`, `tcp.py`, `dot.py` connection reuse, timeouts, and error mapping.
- DoH transport:
  - Prefer `httpx` (if not already) for HTTP/2, connection pooling, TLS verification, and per-host pools.
  - Support GET/POST with proper caching headers; forbid hop-by-hop header injection.
- DoT transport:
  - Ensure SNI is set, ALPN `dot` if applicable, and certificate verification by default.
- Add upstream health-check and circuit breaker strategy; configurable policies (fail-fast, round-robin with health, etc.).

## 9. Caching strategy improvements

- Implement RFC 2308 negative caching and TTL derivation from SOA MINIMUM/NXTTL.
- Add min/max cache TTL clamping; consider serve-stale-while-revalidate for resiliency.
- De-duplicate concurrent in-flight identical queries (request coalescing).
- Expand cache key to include at least `qclass` and, optionally, DO bit / DNSSEC mode.
- Optionally, cache DNSSEC records (DNSKEY/DS) separately with longer TTLs.

## 10. Configuration and hot-reload architecture

- Introduce an `App` / `RuntimeConfig` object encapsulating immutable runtime config, plugins, cache, stats, and listeners.
- Use RCU-style swap on reload: build a new instance, then atomically replace references used by handlers instead of mutating class attributes.
- Decouple signal handling from business logic; provide an HTTP admin endpoint to trigger reload in addition to `SIGUSR1`.
- Validate and diff configs on reload; surface non-disruptive errors without tearing down working state.

## 11. Plugin system hardening and ergonomics

- Ensure `BasePlugin` has clear docstrings (inputs/outputs, behavior) and example usage for non-trivial methods.
- Define a typed `PluginContext` (dataclass or similar) with request/response hooks, client info, timers, and per-request state.
- Enforce plugin timeouts and error isolation (exceptions do not crash pipeline; collect plugin error metrics).
- Clarify plugin priority and short-circuit semantics; document in `BasePlugin`.
- Ensure terminology uses `allowlist`/`blocklist` consistently in docs, logs, and plugin configs (while preserving backward-compatible aliases).

## 12. Stats, observability, and admin API

- Add optional Prometheus `/metrics` endpoint with counters, histograms, and gauges (per-upstream latency, cache hit ratio, plugin errors, etc.).
- Add structured JSON logging mode and per-request trace IDs for correlation.
- Expand admin FastAPI endpoints to expose: live (redacted) config snapshot, upstream health, plugin registry state, and stats reset controls.

## 13. Bug triage and minimal reproductions

- From earlier analysis, enumerate suspected bugs:
  - Double-caching / double-send issues in `DNSUDPHandler.handle` and SERVFAIL paths.
  - Inconsistent TTL behavior between `_cache_store_if_applicable` and `compute_effective_ttl`.
  - EDNS/DNSSEC handling differences between UDP and `resolve_query_bytes`.
- For each suspected bug, add a focused failing test under `tests/` to reproduce.
- Prioritize by impact: correctness first, then performance and ergonomics.

## 14. Test suite enhancements

- Add property-based tests (e.g. `hypothesis`) for cache TTL and failover invariants.
- Add integration tests for each transport (UDP/TCP/DoT/DoH) including TLS verify modes and header handling.
- Add DNSSEC mode tests for AD passthrough vs. local validation; include DO/CD/AD bit matrices.
- Add tests for signal- and HTTP-triggered reload; ensure no dropped requests and that state swaps are atomic.
- Fuzz parser paths with malformed packets and oversized EDNS payloads.

## 15. Performance benchmarking and profiling

- Prepare reproducible benchmarks:
  - `dnsperf` or similar load to UDP/TCP; `vegeta`/`httpx` for DoH.
  - Scenarios: cache-hit, cache-miss, mixed, TC fallback, multi-upstream with failures.
- Profile hot paths:
  - `py-spy` or `perf` to generate flamegraphs under load.
  - `cProfile` for targeted runs; memory profiling for cache growth.
- Set target SLOs (e.g., p99 latency under given QPS, CPU/memory budget) and track before/after.

## 16. Prioritized implementation plan (small PRs)

- Batch 1 (correctness):
  - Fix TC fallback and SERVFAIL paths.
  - Unify caching behavior around `compute_effective_ttl` and RFC 2308.
  - Harden EDNS/DO handling and DNSSEC validation mode logic.
- Batch 2 (stability):
  - Introduce `RuntimeConfig`/`App` and RCU-style reload.
  - Improve plugin context and error isolation.
  - Add upstream health checks.
- Batch 3 (performance):
  - Optimize DoH via pooled HTTP clients.
  - Add request coalescing and optional serve-stale.
- Batch 4 (DX/QA):
  - Enforce `ruff` + `mypy` in CI.
  - Add Prometheus metrics and structured logs.

## 17. CI/CD and repo hygiene

- Add CI workflow (e.g., GitHub Actions):
  - Lint (`ruff`/`black`), type-check (`mypy`), and test (`pytest`) on Python 3.10–3.12.
  - Upload coverage to a service like Codecov (optional).
- Add `pre-commit` hooks: `black`, `ruff`, end-of-file-fixer, mixed-line-ending, trailing-whitespace.
- Pin or range-pin critical dependencies; enable automated dependency updates.

## 18. Documentation updates and diagrams

- Update `README.md` and `README-DEV.md` to reflect any new behaviors (DNSSEC, caching semantics, reload behavior, metrics endpoints).
- Add configuration reference for new settings (health checks, serve-stale, metrics, plugin timeouts).
- Regenerate workflow diagrams (`make workflow-diagrams`) and include them under `images/`.
- Ensure terminology uses `allowlist`/`blocklist` throughout; review examples and tests for consistency.

## 19. Final holistic review

- Produce a short internal report with:
  - Findings per module (issue/opportunity).
  - Concrete recommendations with implemented or planned code changes.
  - Risk/benefit and complexity estimates.
  - Updated test plan and benchmark results.
- Use this report to drive the next round of changes and long-term roadmap.
