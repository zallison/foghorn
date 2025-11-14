# Foghorn Developer Guide

This document contains developer-facing details: architecture, transports, plugins, logging, statistics, signals, and testing. For end‑users and configuration examples, see README.md.

## Breaking changes

This release introduces a few developer-visible breaking changes:

- **Upstream config normalization**: `src/foghorn/main.py.normalize_upstream_config` no longer accepts `cfg['upstream']` as a single mapping with optional `timeout_ms`. Only list-based upstreams are supported; callers must ensure YAML uses the list form.
- **UpstreamRouterPlugin routes**: `src/foghorn/plugins/upstream_router.py` now normalizes routes exclusively from `routes[*].upstreams`. The legacy `routes[*].upstream` single mapping is removed.
- **BasePlugin priority**: `src/foghorn/plugins/base.py` no longer honors the legacy `priority` key. Only `pre_priority` and `post_priority` are used, with the same clamping semantics as before.
- **DoH server shim**: the legacy asyncio-based `foghorn.doh_server.serve_doh` entrypoint has been removed. All DoH usage should go through `foghorn.doh_api.start_doh_server`; YAML `listen.doh` behavior is unchanged.

## Architecture Overview

- Entry: `src/foghorn/main.py` parses YAML, initializes logging/plugins, starts listeners, installs signal handlers.
- Downstream servers:
  - UDP 53: `src/foghorn/udp_server.py` (ThreadingUDPServer wrapper) — handler logic lives in `src/foghorn/server.py`.
  - TCP 53: `src/foghorn/tcp_server.py` (length‑prefixed, persistent connections, RFC 7766; asyncio with threaded fallback).
  - DoT 853: `src/foghorn/dot_server.py` (TLS, RFC 7858; asyncio).
  - DoH 8053: `src/foghorn/doh_server.py` (HTTP/1.1 minimal parser, RFC 8484; optional TLS).
- Upstream transports:
  - UDP: `src/foghorn/transports/udp.py` (dnslib send)
  - TCP: `src/foghorn/transports/tcp.py` with connection pooling
  - DoT: `src/foghorn/transports/dot.py` with connection pooling
  - DoH: `src/foghorn/transports/doh.py` (stdlib http.client; GET/POST; TLS verification controls)
- Plugins: `src/foghorn/plugins/*`, discovered via `plugins/registry.py`. Hooks: `pre_resolve`, `post_resolve`. Aliases supported (e.g., `acl`, `router`, `new_domain`, `filter`).
- Cache: `src/foghorn/cache.py` TTLCache with opportunistic cleanup.

## Request Pipeline

1) Parse query (dnslib)
2) Pre‑plugins (allow/deny/override)
3) Cache lookup
4) Upstream forward with failover (UDP/TCP/DoT/DoH)
5) Post‑plugins (modify/deny)
6) Cache store (NOERROR+answers)
7) Send response (request ID preserved)

When `dnssec.mode` is `validate`, EDNS DO is set and validation depends on `dnssec.validation`:
- `upstream_ad`: require upstream AD bit; otherwise respond SERVFAIL
- `local` (experimental): local validation; behavior may change

## Transports and Pooling

- TCP/DoT clients maintain a simple LIFO pool (default `max_connections: 32`, `idle_timeout_ms: 30000`). One in‑flight query per connection; concurrency by acquiring multiple connections.
- Pools live in module globals keyed by upstream parameters.
- DoT uses `ssl.SSLContext` with TLS ≥1.2; SNI/verification configurable per upstream (`tls.server_name`, `tls.verify`).
- DoH client supports POST (binary body) and GET (`?dns=` base64url without padding). TLS verification is configurable via `verify` and optional `ca_file`.

## Configuration (highlights)

- Listeners under `listen.{udp,tcp,dot,doh}` with `enabled`, `host`, `port`. DoT/DoH accept `cert_file` and `key_file` (optional for DoH if plain HTTP is desired).
- Upstreams accept optional `transport: udp|tcp|dot|doh`. For DoT set `tls.server_name`, `tls.verify`. For DoH set `url`, optional `method`, `headers`, and `tls.verify`/`tls.ca_file`.
- `dnssec.mode: ignore|passthrough|validate`, `dnssec.validation: upstream_ad|local` (local is experimental), `dnssec.udp_payload_size` (default 1232).
- `min_cache_ttl` (seconds) clamps cache expiry floor; negative values are clamped to 0.

## Logging and Statistics

- Logging is configured via the YAML `logging` section (see README.md for a quickstart). Format uses bracketed levels and UTC timestamps.
- Statistics: enable with `statistics.enabled`. A `StatsReporter` periodically logs JSON snapshots with counters/histograms. Tunables include `interval_seconds`, `reset_on_log`, `track_uniques`, `include_qtype_breakdown`, `include_top_clients`, `include_top_domains`, `top_n`, and `track_latency`.
- When `track_latency: true`, two latency histogram fields are emitted:
  - `latency`: cumulative statistics since start (or last reset if `reset_on_log: true`)
  - `latency_recent`: statistics only for queries since the last stats emission; always resets after each log interval
  Both fields have the same schema: `count`, `min_ms`, `max_ms`, `avg_ms`, `p50_ms`, `p90_ms`, `p99_ms`.

## Signals

- SIGUSR1: reloads configuration from `--config`, re‑applies logging and DNSSEC knobs, and if statistics are enabled with `reset_on_sigusr1: true`, logs a JSON snapshot and resets the counters.
- SIGUSR2: invokes `handle_sigusr2()` on all active plugins if implemented (useful for ad‑hoc plugin actions).

## Testing

- Unit tests: run `pytest`.
- Integration (manual):
  - TCP: `dig +tcp @127.0.0.1 -p 5353 example.com A`
  - DoT: `kdig +tls @127.0.0.1 -p 8853 example.com A`
  - DoH: `curl -s -H 'accept: application/dns-message' --data-binary @query.bin http://127.0.0.1:8053/dns-query`
  - DNSSEC passthrough: `kdig +dnssec @127.0.0.1 -p 5353 example.com A`

## Development

- Code formatting: run `black src tests`.
- Plugin development: inherit from `BasePlugin`, implement `pre_resolve` and/or `post_resolve`. Use the alias registry (see `plugins/registry.py`) or full dotted class paths. Prefer the terms “allowlist” and “blocklist” in documentation.

## JSON Lines (JSONL) format

JSON Lines is a convenient format for streaming structured data where each line is an independent JSON object.

- Encoding: UTF-8
- Structure: one JSON object per line; no outer array or multi-line objects
- Whitespace: newlines delimit records; trailing spaces are allowed but discouraged
- Comments: not allowed inside JSON; files may still contain shell-style comments (`# ...`) only when a loader explicitly states it supports them
- Commas: no trailing commas; each line must be valid JSON by itself
- Mixing formats: where documented, loaders may accept plain-text lines and JSONL in the same file, detected line-by-line

Why we use it
- Stream-friendly: process large files incrementally with O(1) memory
- Append-friendly: safe to append new objects without reformatting
- Human-diffable: line-oriented diffs stay readable

General guidelines for contributors
- Keep each line a single JSON object with a minimal schema; avoid nesting unless necessary
- Validate inputs; on parse errors, prefer logging-and-skip over hard failure for data files
- Do not retain parser state between calls; each file/line should be handled independently
- Use allowlist/blocklist terminology in user-facing fields and docs

Examples

Plain JSONL file:
```json path=null start=null
{"domain": "good.com", "mode": "allow"}
{"domain": "bad.com", "mode": "deny"}
{"domain": "neutral.com"}
```

Mixed with plain text (only when the loader documents support):
```text path=null start=null
# allowlist
good.com
{"domain": "bad.com", "mode": "deny"}
```

Project-specific notes
- FilterPlugin is the only component that reads JSONL from external files; specifically the file-backed input fields: allowed_domains_files, allowlist_files, blocked_domains_files, blocklist_files, blocked_patterns_files, blocked_keywords_files, blocked_ips_files
- The core YAML config does not accept JSONL; it only references which files to load
- Statistics snapshots are logged as single-line JSON objects (conceptually JSONL when collected)

## FilterPlugin file parsing internals

FilterPlugin supports file-backed inputs for domains, patterns, keywords, and IP rules. Parsing is layered to keep responsibilities clear and avoid state leakage.

Helpers (in src/foghorn/plugins/filter.py):
- _expand_globs(paths: list[str]) -> list[str]
  - Expands globs and validates that each path either exists or matches at least one file; raises FileNotFoundError on misses.
- _iter_noncomment_lines(path: str) -> Iterator[tuple[int, str]]
  - Yields (lineno, stripped_line) for non-empty, non-#-comment lines.
- _load_patterns_from_file(path: str) -> list[Pattern]
  - Accepts plain lines (regex) and JSON Lines: {"pattern": "...", "flags": ["IGNORECASE"]}; compiles with re.IGNORECASE by default; logs compile errors and skips invalid entries.
- _load_keywords_from_file(path: str) -> set[str]
  - Accepts plain lines (keyword) and JSON Lines: {"keyword": "..."}; lowercases and accumulates.
- _load_blocked_ips_from_file(path: str) -> None
  - Accepts simple lines (IP or CIDR -> deny), CSV lines (ip,action[,replace_with]), and JSON Lines: {"ip": "...", "action": "deny|remove|replace", "replace_with": "IP"}.
  - Validates IP/CIDR and replacement IPs; unknown actions default to deny; logs and skips invalid entries.
- load_list_from_file(filename: str, mode: str = 'deny')
  - Domains loader; accepts plain lines (domain) and JSON Lines {"domain": "...", "mode": "allow|deny"}; per-line mode overrides provided mode. Persists into SQLite table blocked_domains with last-write-wins semantics.

Domain precedence (implemented in __init__ load order):
1) allowed_domains_files / allowlist_files
2) blocked_domains_files / blocklist_files
3) inline allowed_domains
4) inline blocked_domains

IPs evaluation:
- Exact IP rules override network rules when both match.
- If any rule with action=deny matches an answer IP, the entire response is denied.
- action=remove: answer RRs matching the rule are removed; if all A/AAAA are removed, NXDOMAIN is returned.
- action=replace: A/AAAA RRs are rewritten to the replacement IP (version must match), producing an override response.

Logging and errors:
- All loaders log file:line for invalid entries and continue.
- Glob expansion raises FileNotFoundError when nothing matches and the path doesn’t exist.

Testing notes:
- tests/plugins/test_filter_plugin.py covers core behavior and error paths.
- tests/plugins/test_filter_plugin_files_extra.py covers globs and file-backed inputs (plain/CSV).
- tests/plugins/test_filter_plugin_jsonl.py covers JSON Lines for domains, patterns, keywords.

## Future Work

- Full local DNSSEC validation with trust anchor management.
- Additional metrics endpoint and connection reuse optimizations (e.g., TLS session resumption).
