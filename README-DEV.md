# Foghorn Developer Guide

This document contains developer-facing details: architecture, transports, plugins, logging, statistics, signals, and testing. For end‑users and configuration examples, see README.md.

## Breaking changes

This release introduces a few developer-visible breaking changes:

- **Upstream config normalization**: `src/foghorn/main.py.normalize_upstream_config` no longer accepts `cfg['upstream']` as a single mapping with optional `timeout_ms`. Only list-based upstreams are supported; callers must ensure YAML uses the list form.
- **UpstreamRouterPlugin routes**: `src/foghorn/plugins/upstream_router.py` now normalizes routes exclusively from `routes[*].upstreams`. The legacy `routes[*].upstream` single mapping is removed.
- **BasePlugin priorities**: `src/foghorn/plugins/base.py` no longer honors the legacy `priority` key. Plugins must use `pre_priority`, `post_priority`, and (for setup-aware plugins) `setup_priority`. All three obey the same clamping semantics (1–255), and `setup_priority` falls back to the config-specified `pre_priority` or to the class attribute when omitted.
- **DoH server shim**: the legacy asyncio-based `foghorn.doh_server.serve_doh` entrypoint has been removed. All DoH usage should go through `foghorn.doh_api.start_doh_server`; YAML `listen.doh` behavior is unchanged (requests still go through the standard plugin/caching pipeline).

## Architecture Overview

- Entry: `src/foghorn/main.py` parses YAML, initializes logging/plugins, starts listeners, installs signal handlers.
- Downstream servers:
  - UDP 5333: `src/foghorn/udp_server.py` (ThreadingUDPServer wrapper) — handler logic lives in `src/foghorn/server.py`.
  - TCP 5333: `src/foghorn/tcp_server.py` (length‑prefixed, persistent connections, RFC 7766; asyncio with threaded fallback).
  - DoT 1853: `src/foghorn/dot_server.py` (TLS, RFC 7858; asyncio).
  - DoH 8153: `src/foghorn/doh_server.py` (HTTP/1.1 minimal parser, RFC 8484; optional TLS).
- Upstream transports:
  - UDP: `src/foghorn/transports/udp.py` (dnslib send)
  - TCP: `src/foghorn/transports/tcp.py` with connection pooling
  - DoT: `src/foghorn/transports/dot.py` with connection pooling
  - DoH: `src/foghorn/transports/doh.py` (stdlib http.client; GET/POST; TLS verification controls)
- Plugins: `src/foghorn/plugins/*`, discovered via `plugins/registry.py`. Hooks: `pre_resolve`, `post_resolve`. Aliases supported (e.g., `acl`, `router`, `new_domain`, `filter`, `custom`, `records`).
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

- Listeners under `listen.{udp,tcp,dot,doh}` with `enabled`, `host`, `port`. DoT/DoH accept `cert_file` and `key_file` (optional for DoH if plain HTTP is desired). The DoH listener is implemented via `foghorn.doh_api.start_doh_server` and shares the same resolver/plugin pipeline as UDP/TCP/DoT.
- Upstreams accept optional `transport: udp|tcp|dot|doh`. For DoT set `tls.server_name`, `tls.verify`. For DoH set `url`, optional `method`, `headers`, and `tls.verify`/`tls.ca_file`.
- `dnssec.mode: ignore|passthrough|validate`, `dnssec.validation: upstream_ad|local` (local is experimental), `dnssec.udp_payload_size` (default 1232).
- `min_cache_ttl` (seconds) clamps cache expiry floor; negative values are clamped to 0.

## Plugin lifecycle and priorities

- Plugins subclass `BasePlugin` and are discovered via `plugins/registry.py` using aliases (e.g., `acl`, `router`, `new_domain`, `filter`).
- Each plugin instance has three priority attributes:
  - `pre_priority`: ordering for `pre_resolve` hooks (lower runs first).
  - `post_priority`: ordering for `post_resolve` hooks (lower runs first).
  - `setup_priority`: ordering for `setup()` during the startup phase (lower runs first).
- `BasePlugin.__init__` accepts `pre_priority`, `post_priority`, and `setup_priority` in the plugin config. Values are coerced to integers, clamped to [1, 255], and fall back to class attributes when invalid.
- `setup_priority` resolution:
  - Prefer explicit `setup_priority` from config.
  - Otherwise fall back to config-provided `pre_priority` for setup-aware plugins.
  - Otherwise fall back to the class attribute `setup_priority` (default 50).
- `main.run_setup_plugins()`:
  - Filters the instantiated plugin list down to those that override `BasePlugin.setup`.
  - Collects `(setup_priority, plugin)` pairs and runs `setup()` in ascending `setup_priority` order (stable sort; original registration order is preserved for ties).
  - Reads `abort_on_failure` from each plugin’s `config` (defaults to `True`); if `setup()` raises and `abort_on_failure` is true, startup is aborted with `RuntimeError`. If `abort_on_failure` is false, the error is logged and startup continues.
- Example setup ordering (ListDownloader and Filter):
  - `ListDownloader` defines `setup_priority = 15` so it runs early, downloads lists, and validates them before other plugins.
  - `FilterPlugin` typically uses a higher `setup_priority` (for example 20), so it runs after ListDownloader and can safely load the downloaded files.
  - User config may override `setup_priority` on a per-plugin basis when composing plugin chains.

## BasePlugin targeting and TTL cache

`BasePlugin` implements optional, shared client‑targeting semantics for all
plugin subclasses via three configuration keys:

- `targets`: list of CIDR/IP strings (or a single string) defining an allow‑set
  of client networks for this plugin.
- `targets_ignore`: list of CIDR/IP strings to exclude from targeting even when
  they match `targets`.
- `targets_cache_ttl_seconds`: integer TTL (seconds) for an internal
  `FoghornTTLCache` that memoizes per‑client decisions.

Runtime behavior (`BasePlugin.targets(ctx) -> bool`):

- When both `_target_networks` and `_ignore_networks` are empty (no config
  provided), the method returns `True` and bypasses the cache; the plugin
  applies to all clients.
- When `targets` and/or `targets_ignore` are configured, the method first
  checks `_ignore_networks` (deny‑list wins), then `_target_networks`:
  - `targets` only: client is targeted iff its IP is in at least one target
    network.
  - `targets_ignore` only: client is targeted iff its IP is **not** in any
    ignore network (inverted logic).
  - both: client is targeted iff it is **not** in any ignore network and is in
    at least one target network.
- Decisions are cached per `(client_ip, 0)` key as `'1'`/`'0'` bytes for the
  configured TTL; cache lookups are a fast path on hot clients under load.

Core plugins that currently respect `targets()` include AccessControl,
Filter, Greylist, NewDomainFilter, UpstreamRouter, FlakyServer, Examples,
and EtcHosts. Implementers of new plugins are encouraged to call
`self.targets(ctx)` early in their `pre_resolve`/`post_resolve` hooks when
client‑scoped behavior is desired.

## Logging and Statistics

- Logging is configured via the YAML `logging` section (see README.md for a quickstart). Format uses bracketed levels and UTC timestamps.
- Statistics: enable with `statistics.enabled`. A `StatsReporter` periodically logs JSON snapshots with counters/histograms. Tunables include `interval_seconds`, `reset_on_log`, `track_uniques`, `include_qtype_breakdown`, `include_top_clients`, `include_top_domains`, `top_n`, and `track_latency`.
- When `track_latency: true`, two latency histogram fields are emitted:
  - `latency`: cumulative statistics since start (or last reset if `reset_on_log: true`)
  - `latency_recent`: statistics only for queries since the last stats emission; always resets after each log interval
  Both fields have the same schema: `count`, `min_ms`, `max_ms`, `avg_ms`, `p50_ms`, `p90_ms`, `p99_ms`.

## Signals

- SIGUSR1: notifies active plugins (via `handle_sigusr2()`) and, when statistics are enabled with `sigusr2_resets_stats: true`, resets in-memory statistics counters.
- SIGUSR2: identical behavior to SIGUSR1; retained for backwards compatibility so existing tooling can continue to send either signal.
- SIGHUP: requests a clean shutdown with exit code 0; intended for supervisors (e.g., systemd) to restart Foghorn with a new configuration. The `/config/save` admin endpoint writes the updated config file and then, after a brief delay, sends SIGHUP to the main process.

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

## ZoneRecords plugin internals

`ZoneRecords` (formerly `CustomRecords`) is a pre-resolve plugin that answers
selected queries directly from configured records files and can act as an
authoritative server for zones defined in those files.

- Location: `src/foghorn/plugins/zone-records.py`
- Aliases: `zone`, `zone_records`, `custom`, `records`
- Hooks: implements `setup()` and `pre_resolve()`; no post-resolve hook

Records files are parsed line-by-line; each non-empty, non-comment line must
have the shape:

`<domain>|<qtype>|<ttl>|<value>`

- `domain` is normalized to lower-case without a trailing dot for lookup.
- `qtype` may be a numeric code or mnemonic; resolution uses `dnslib.QTYPE`.
- `ttl` must be a non-negative integer.
- `value` is preserved as a string and later converted to RRs via
  `RR.fromZone` when building responses.

Configuration:

- `file_path`: legacy single records file (string)
- `file_paths`: list of records files; when both are supplied the legacy
  `file_path` is appended to the list
- `watchdog_enabled` (default `True` when omitted): when truthy and
  `watchdog` is importable, start a per-directory observer that reloads
  records on writes/creates/moves
- `watchdog_min_interval_seconds` (default 1.0): minimum spacing between
  reloads triggered by filesystem events; additional events within the
  interval schedule a deferred reload via a background timer
- `watchdog_poll_interval_seconds` (default 0.0): when greater than zero,
  enables a stat-based polling loop that compares `(inode, size, mtime)`
  snapshots for each configured file; useful on filesystems where events
  are unreliable

Semantics:

- Records from multiple files are merged in configuration order; for each
  `(domain, qtype)` key the first TTL is kept and values are de-duplicated
  while preserving first-seen order across files.
- `pre_resolve()` performs a read under an optional `_records_lock` and, when
  a mapping entry exists, constructs an authoritative `DNSRecord` with all
  configured answers in the stored order and returns
  `PluginDecision(action="override", response=...)`.
- Background reloads replace the entire `records` mapping atomically under
  `_records_lock` to avoid exposing partially updated state.

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
