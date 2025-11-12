# Foghorn Developer Guide

This document contains developer-facing details: architecture, transports, plugins, logging, statistics, signals, and testing. For end‑users and configuration examples, see README.md.

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

## Future Work

- Full local DNSSEC validation with trust anchor management.
- Additional metrics endpoint and connection reuse optimizations (e.g., TLS session resumption).
