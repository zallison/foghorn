# Foghorn Developer Guide

This document contains developer-facing details: architecture, transports, plugins, logging, and testing. For end‑users and configuration examples, see README.md.

## Architecture Overview

- Entry: `foghorn/main.py` parses YAML, initializes logging/plugins, starts listeners.
- UDP server: `foghorn/server.py` (ThreadingUDPServer). Now delegates transport selection per upstream.
- Downstream servers (asyncio):
  - TCP 53: `foghorn/tcp_server.py` (length‑prefixed, persistent connections, RFC 7766)
  - DoT 853: `foghorn/dot_server.py` (TLS, RFC 7858)
- Upstream transports:
  - UDP (dnslib `DNSRecord.send`)
  - TCP: `foghorn/transports/tcp.py` with pooling
  - DoT: `foghorn/transports/dot.py` with pooling
- Plugins: `foghorn/plugins/*`, discovered via `plugins/registry.py`. Hooks: `pre_resolve`, `post_resolve`.
- Cache: `foghorn/cache.py` TTLCache with opportunistic cleanup.

## Request Pipeline

1) Parse query (dnslib)
2) Pre‑plugins (deny/override/allow)
3) Cache lookup
4) Upstream forward with failover (UDP/TCP/DoT)
5) Post‑plugins (modify/deny)
6) Cache store (NOERROR+answers)
7) Send response (ID fixed)

When `dnssec.mode` is `validate`, EDNS DO is set and upstream responses are required to carry AD; otherwise SERVFAIL is returned.

## Transports and Pooling

- TCP/DoT clients maintain a simple LIFO pool (max_connections default 32, idle timeout 30s). One in‑flight query per connection; concurrency is achieved by acquiring multiple connections.
- Pools live in module globals keyed by upstream parameters.
- DoT uses `ssl.SSLContext` with TLS ≥1.2, SNI/verification configurable per upstream.

## DNSSEC Modes

- `ignore`: do not advertise DO; no DNSSEC data requested.
- `passthrough`: advertise DO; return DNSSEC RRs unmodified; forward AD if present.
- `validate`: advertise DO; require upstream AD bit. If AD is missing, respond SERVFAIL. (Local chain validation is future work.)

## Configuration (highlights)

- Listeners under `listen.{udp,tcp,dot}` with `enabled`, `host`, `port`.
- Upstreams accept optional `transport: udp|tcp|dot`. For `dot`, set `tls.server_name`, `tls.verify`.
- `dnssec.mode: ignore|passthrough|validate`, `dnssec.udp_payload_size` (default 1232).

## Logging and Stats

- Logging configured via YAML; see README.md. Stats collector logs JSON lines with counters/histograms if enabled.

## Testing

- Unit tests: `pytest`.
- Integration (manual):
  - TCP: `dig +tcp @127.0.0.1 -p 5353 example.com A`
  - DoT: `kdig +tls @127.0.0.1 -p 8853 example.com A`
  - DNSSEC passthrough: `kdig +dnssec @127.0.0.1 -p 5353 example.com A`

## Future Work

- Full local DNSSEC validation (dnspython) with trust anchor management.
- Upstream HTTP/2 DoH, downstream /dns-query HTTPS.
- Metrics endpoint and connection reuse optimizations (session resumption).
