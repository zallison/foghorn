# Foghorn DNS RFC Compliance

This document summarizes how Foghorn’s behavior maps onto major DNS-related RFCs. It focuses on what is implemented today, what is close/partial, and what is explicitly out of scope.

## RFC Summary Table

|       RFC | Short Title                                     | Status                                                                 |
|-----------+-------------------------------------------------+------------------------------------------------------------------------|
|      1034 | DNS Concepts and Facilities                     | Implemented (core behavior)                                            |
|      1035 | DNS Implementation and Specification            | Implemented (core behavior)                                            |
|      1996 | DNS NOTIFY                                      | Partially implemented (inbound + outbound for ZoneRecords)             |
|      2136 | Dynamic Updates in the DNS                      | Partially implemented (ZoneRecords DNS UPDATE + TSIG)                  |
|      2308 | Negative Caching of DNS Queries                 | Implemented                                                            |
|      2845 | Secret Key Transaction Authentication for DNS   | Partially implemented (AXFR/IXFR + UPDATE; not general QUERY TSIG)     |
|      4033–4035 | DNSSEC protocol/records/validation          | Partially implemented                                                  |
|      4592 | The Role of Wildcards in the Domain Name System | Partial / intentional non-compliance (leading `*` = one-or-more labels)|
|      5011 | Automated Updates of DNS Security Trust Anchors | Implemented                                                            |
|      5936 | DNS Zone Transfer Protocol (AXFR/IXFR)          | Partially implemented (AXFR client/server; IXFR server as full AXFR)   |
|      6891 | Extension Mechanisms for DNS (EDNS(0))          | Partially implemented                                                  |
|      7766 | DNS over TCP                                    | Implemented                                                            |
|      7858 | DNS over TLS (DoT)                              | Implemented                                                            |
|      7871 | Client Subnet in DNS Queries (ECS)              | Partially implemented (trust-gated forward mode)                       |
|      7873 | Domain Name System (DNS) Cookies                | Partially implemented (cache-safe rebind/strip; no server cookie auth) |
|      7958 | DNSSEC Trust Anchor Publication for the Root    | Implemented                                                            |
|      8484 | DNS over HTTPS (DoH)                            | Implemented                                                            |
|      8914 | Extended DNS Errors                             | Partially implemented (policy/upstream failures; default on)           |
|      9230 | Oblivious DNS over HTTPS (ODoH)                 | Not implemented / out of scope                                         |
|      9250 | DNS over QUIC (DoQ)                             | Not implemented / out of scope                                         |

Status legend:

- **Implemented** – Actively used on the wire and tested; behavior is meant to be compatible with the RFC for the covered use cases.
- **Implemented (core behavior)** – Normal query/response flows follow the RFCs; Foghorn does not yet aim to implement every corner case.
- **Partially implemented** – Only the subset needed for Foghorn’s current feature set is present.
- **Experimental / partial** – Feature is available but marked experimental and may not cover all RFC scenarios.
- **Not implemented / out of scope** – No explicit support; queries may still be forwarded opaquely by upstreams.

---

## 1. Core DNS (RFC 1034, RFC 1035)

Foghorn is a caching, policy-aware DNS forwarder. For standard query/response flows:

- Uses `dnslib` for parsing and building DNS messages in line with RFC 1034/1035.
- Preserves the DNS ID across responses.
- Handles typical RR types (A, AAAA, CNAME, TXT, etc.) and standard RCODEs.
- Acts primarily as a caching resolver, either **forwarding** or **recursive**,
  with optional authoritative-style answers provided by the ZoneRecords plugin
  (static records, BIND zones, AXFR-backed zones, and optional DNS UPDATE state).
- Non-QUERY opcodes (NOTIFY, UPDATE, and others) are dispatched through the
  shared opcode path to plugins that implement `handle_opcode()`, with size and
  per-source rate limits applied before plugin handling.

In practice, for normal stub-resolver traffic, Foghorn behaves like a conventional RFC 1034/1035-compliant caching resolver.

Optional operational knobs that are policy rather than protocol requirements:

- `server.features.refuse_any` may refuse QTYPE ANY with `REFUSED` as an amplification mitigation.
- Recursive mode defaults to allowing private next-hop glue for split-horizon deployments; set `server.resolver.allow_private_destinations: false` to skip non-global glue, with optional `destination_allowlist` exceptions.
- Search-domain qualification is available via `server.resolver.search` and is applied before cache keys, plugin dispatch, stats, and upstream forwarding (DNSSEC RR types are excluded from qualification).

---

## 2. Transports

### 2.1 DNS over UDP and TCP (RFC 1035, RFC 7766)

- **UDP:**
  - Standard UDP DNS listener for queries (asyncio by default).
  - Uses the same parsing, caching, plugin, and statistics pipeline as other transports.
  - Supports in-flight caps, optional response ceilings, and `max_query_bytes` packet size limits.
- **TCP (RFC 7766):**
  - Implements length-prefixed DNS messages over TCP.
  - Uses connection pooling for upstream TCP resolvers.
  - Supports persistent connections with one in-flight query per connection at a time.
  - Applies connection/query/idle hardening knobs on both asyncio and threaded TCP paths.

Foghorn follows the protocol requirements in RFC 7766 for framing and basic
connection handling; some of the more detailed operational guidance (e.g.,
highly tuned limits under extreme load) is handled in a straightforward but not
elaborate way.

### 2.2 DNS over TLS (DoT) – RFC 7858

- Downstream DoT server:
  - Asyncio-based TLS listener that accepts length-prefixed DNS queries over TLS.
  - Uses TLS 1.2+ with configurable certificate/key paths.
- Upstream DoT client:
  - Uses an `ssl.SSLContext` with a minimum TLS version of 1.2.
  - Supports SNI (`server_name`) and certificate verification controls per upstream.

Behavior is designed to match RFC 7858’s framing and TLS requirements for
typical resolver use. DoT is also used for optional ZoneRecords AXFR client
pulls and outbound NOTIFY targets.

### 2.3 DNS over HTTPS (DoH) – RFC 8484

- **Upstream DoH client:**
  - Supports both `POST` with `Content-Type: application/dns-message` and `GET` with `?dns=<base64url>`.
  - Uses base64url encoding **without padding** for the `dns` query parameter.
  - Validates HTTPS connections with configurable verification and CA bundle settings.
- **Downstream DoH server:**
  - Exposes `/dns-query` over HTTP/HTTPS using both FastAPI-based and threaded HTTP handlers.
  - Implements `GET /dns-query?dns=<base64url>` and `POST /dns-query` with `application/dns-message`.
  - Forwards wire-format DNS queries through the same resolver pipeline as UDP/TCP/DoT.
  - Enforces request-size caps (GET decode and POST body) and returns HTTP 413 for oversized requests.

These code paths explicitly target RFC 8484 semantics for both client and server roles.

---

## 3. EDNS(0), Cookies, ECS, EDE, and Negative Caching

### 3.1 EDNS(0) – RFC 6891 (Partial)

Foghorn implements a standards-aware subset of EDNS(0), centralized in
`src/foghorn/servers/edns_utils.py`:

- Ensures there is exactly one OPT record in outgoing upstream queries in forward mode.
- Mirrors a client's EDNS version and advertised UDP payload size when present, clamped by a configurable `edns_udp_payload` (default 1232).
- When a client does **not** send EDNS, assumes the classic 512-byte UDP size and marks oversized responses as truncated (TC=1) to encourage TCP fallback.
- Sets the DO bit in EDNS flags when `dnssec.mode` requires it (`passthrough` / `validate`) and clears it in `ignore` mode, while preserving other EDNS flag bits.
- Supports constrained ECS and COOKIE handling (see below).
- Other advanced EDNS options (for example NSID) are not implemented as first-class features.

### 3.2 DNS Cookies – RFC 7873 (Partial)

Foghorn does **not** implement full DNS Cookie authentication (no server-secret
cookie generation/validation as a first-class anti-amplification feature).

It does implement **cache-safe COOKIE hygiene** on the resolver response path:

- Strips upstream DNS COOKIE options before caching responses.
- Rebinds COOKIE on each client response to the active request’s client cookie.
- Removes COOKIE from responses when the request carried no COOKIE, so stale
  upstream cookies are not leaked across clients or cache hits.

This keeps shared caching correct when clients or upstreams emit COOKIE options,
without claiming full RFC 7873 server-cookie semantics.

### 3.3 Client Subnet (ECS) – RFC 7871 (Partial)

Supports a constrained ECS flow in forward mode when enabled:

- Parses inbound ECS from client OPT records.
- Trust-gates inbound ECS using `ecs.trusted_listeners` and/or `ecs.trusted_client_cidrs`.
- Forwards only trusted inbound ECS when `ecs.forward_inbound` is enabled.
- Strips untrusted inbound ECS before optional trusted/synthesized ECS injection.
- Optionally synthesizes outbound ECS from transport source IP when `ecs.synthesize_from_client_ip` is enabled.
- Preserves no-OPT fallback behavior (no synthetic OPT creation for ECS on requests without EDNS).
- Bypasses shared response caching when ECS context affects upstream query semantics.
- Query-result metadata can include source/effective-target/ECS fields for ECS-aware requests.

Canonical config lives under `server.features` ECS toggles, with compatibility
aliases retained for older key names.

### 3.4 Extended DNS Errors – RFC 8914 (Partial)

When EDE is enabled and the client advertises EDNS(0), Foghorn can attach
RFC 8914 Extended DNS Error options to certain synthetic responses (for example
policy denies, rate limits, and upstream failures) while leaving RCODE semantics
unchanged.

- EDE is **enabled by default** (`server.features.enable_ede`; legacy alias
  `server.enable_ede` is still accepted).
- Upstream-provided EDE options are forwarded opaquely.
- RateLimit can attach EDE code 17 (“Rate-Limited”).
- Query-log filtering and admin diagnostics can use `ede_code`.
- Full DNSSEC-related EDE coverage is not implemented.

### 3.5 Negative Caching – RFC 2308

Foghorn’s cache logic for negative and referral responses follows the guidance from RFC 2308:

- For **NXDOMAIN** and **NODATA** responses with an SOA in the authority section:
  - Uses a helper that inspects SOA TTL and minimum TTL (minttl) fields.
  - Derives a negative cache TTL from these values, falling back to a configured minimum when necessary.
- For **delegation/referral** responses (NOERROR with no answers but NS records in the authority section):
  - Uses NS TTLs as a basis for caching, again with a fallback TTL when needed.

This yields negative and referral caching behavior compatible with RFC 2308 for typical responses.

---

## 4. DNSSEC

### 4.1 Overview

Foghorn supports three DNSSEC modes via configuration:

- `ignore` – Do not advertise DO; DNSSEC data is not requested.
- `passthrough` – Advertise DO and forward DNSSEC RRs and the upstream AD bit.
- `validate` – Require validation, with a choice of validation strategy:
  - `upstream_ad` – Trust an upstream validator’s AD bit.
  - `local` – Perform local DNSSEC validation (experimental; see below).

### 4.2 Upstream-based validation (AD-bit) – RFCs 4033–4035 (indirect)

When `dnssec.mode: validate` and `dnssec.validation: upstream_ad` are set:

- Foghorn sets DO on outgoing queries and expects upstreams to do full DNSSEC validation.
- If the upstream response carries the AD bit set, Foghorn classifies the answer as **secure**.
- If the AD bit is missing or validation otherwise fails, Foghorn can treat the result as insecure/unsuitable depending on configuration.

In this mode Foghorn does not directly implement all of RFC 4033–4035 itself;
instead it relies on an upstream that does, and uses the AD bit and DNSSEC data
to guide behavior and statistics.

### 4.3 Local validation (experimental) – RFCs 4033–4035, 5011, and 7958

When `dnssec.mode: validate` and `dnssec.validation: local` are set, Foghorn performs its own validation using `dnspython`:

- Uses a baked-in root DNSKEY trust anchor derived from the IANA root anchors (per RFC 7958) as the starting trust anchor.
- Supports automated trust-anchor maintenance paths aligned with RFC 5011 testing/support in-tree.
- Probes for DNSKEY and DS records up the hierarchy to locate the zone apex for a given query.
- Validates DS/DNSKEY chains from the root to the apex.
- Locates the answer RRset and its RRSIG and validates signatures using the apex DNSKEY set.
- Classifies responses as `secure`, `insecure`, `indeterminate`, or `bogus`.
- Can convert locally-classified `bogus` answers into SERVFAIL.
- Applies AD-bit updates in validate mode and treats signed authoritative local
  responses as zone-secure when classification would otherwise be unsigned/bogus.

This mode is explicitly marked **experimental** and does not claim complete
coverage of all DNSSEC edge cases (e.g., complex rollover timing, every
algorithm combination, or unusual record types). It is suitable for
experimentation and modest setups but not yet a full replacement for mature
validators like Unbound/BIND.

### 4.4 Authoritative / ZoneRecords DNSSEC

ZoneRecords can serve DNSSEC-signed data when clients advertise EDNS(0) with DO=1:

- Pre-signed zones via `bind_paths` / inline records (helper: `scripts/generate_zone_dnssec.py`).
- Optional auto-signing via `dnssec_signing` (defaults to enabled when the block is present unless `enabled: false`).
- NSEC3 owner indexes are used to speed negative-proof matching when present.
- Offline/auto signing can emit NSEC3-related material depending on config; see the ZoneRecords guide for current limitations around negative proofs and re-signing on change.

---

## 5. Zone Transfers, NOTIFY, UPDATE, and TSIG

### 5.1 AXFR/IXFR – RFC 5936 (Partial)

Foghorn implements a practical subset of zone transfer behavior around ZoneRecords and `server.axfr`:

**AXFR client (ZoneRecords `axfr_zones`):**

- Full TCP-based AXFR (optional DoT) at startup and on later reloads.
- Optional periodic polling via `poll_interval_seconds` / `axfr_poll_min_interval_seconds`.
- Reload timing via `minimum_reload_time` (honors elapsed time since last load or last inbound NOTIFY).
- Transfer safety: `max_rrs_per_zone`, `max_bytes_per_zone`, retries/backoff, public/private upstream gating.
- Optional TSIG on upstream pulls (`axfr_zones[*].upstreams[*].tsig`).
- DNSSEC classification of transferred zones (`dnssec_state=present|partial|none`) with warnings when material is missing/incomplete; `allow_no_dnssec` defaults to `true` and currently acts as a policy hint/logging control rather than a hard reject of all unsigned transfers.
- No IXFR **client** (incremental pull) support yet.

**AXFR/IXFR server:**

- Available for ZoneRecords-authoritative zones over DNS-over-TCP and DoT when `server.axfr.enabled` is true.
- Streams zone contents bounded by matching SOA records.
- **IXFR is served as a full AXFR-style transfer** (no true delta IXFR yet).
- Hardening via `server.axfr`: `allow_clients`, nested `tsig.keys` / `tsig.key_sources` (legacy `tsig_keys` still accepted), `require_tsig`, `max_zone_rrs`, concurrency/rate/pacing limits, and message size caps.

### 5.2 DNS NOTIFY – RFC 1996 (Partial)

ZoneRecords owns inbound DNS NOTIFY handling through plugin opcode dispatch:

- Inbound NOTIFY is accepted subject to non-QUERY size/rate limits and, when AXFR is enabled, the AXFR client allowlist.
- Optional TSIG verification on signed NOTIFY before plugin dispatch.
- Valid NOTIFY can schedule/coalesce AXFR refresh for matching `axfr_zones`, subject to `minimum_reload_time` and backoff.
- Outbound NOTIFY uses the static `axfr_notify` target list only (TCP or DoT).
  - Targets are not auto-learned from AXFR clients (`axfr_notify_all` is deprecated and ignored).
  - Controls include private-target policy, target allowlist, min interval, and per-target rate limits.
  - Local listener endpoints are skipped to avoid self-loop NOTIFY storms.
- DNS UPDATE commits can also emit NOTIFY according to `dns_update.replication` settings.

Foghorn is not a full primary/secondary authoritative product, but it does implement the NOTIFY flows needed for ZoneRecords hybrid/static + AXFR deployments.

### 5.3 Dynamic Updates – RFC 2136 (Partial)

ZoneRecords implements DNS UPDATE when `dns_update.enabled` is true and the
zone matches a configured `dns_update.zones[]` entry:

- Prerequisite evaluation (RRset existence/nonexistence, name in use).
- ADD/DELETE/REPLACE-style update operations with atomic commits.
- Zone-boundary enforcement to the configured apex.
- TSIG authentication (algorithm/fudge validation); active request authorization is **TSIG-based**.
  - `dns_update.zones[].psk` remains in schema for compatibility/provisioning but is **not** applied on the active UPDATE auth path.
- Per-zone and per-principal allow/block scopes for names and update IPs, plus client IP allowlists.
- Optional persistence journal (replay/compaction), replication role gates, and security/rate limits.
- Post-commit SOA serial bumps and optional NOTIFY fanout.
- UPDATE-managed RRsets take precedence over static sources for the same owner.

See `docs/plugins/resolve/zone_update.md` and
`example_configs/plugin_zone_update_all_options.yaml`.

### 5.4 TSIG – RFC 2845 (Partial)

TSIG is implemented for the zone-management paths that need it:

- Upstream AXFR client transfers (`axfr_zones[*].upstreams[*].tsig`).
- Downstream AXFR/IXFR serving (`server.axfr.require_tsig` + nested `server.axfr.tsig` keys/sources; legacy `tsig_keys` alias retained).
- DNS UPDATE authentication and best-effort signed error responses.
- Best-effort MAC verification for signed non-QUERY opcodes before plugin dispatch; signed messages are refused when no keys are configured.

General recursive QUERY/response TSIG authentication is not a primary feature.

---

## 6. Wildcards – RFC 4592 (Intentional difference)

ZoneRecords wildcard owners use a **non-RFC-4592** rule for leading `*` labels:
a leading `*` matches **one or more** labels (any depth). For example,
`*.example.org` matches both `a.example.org` and `a.b.example.org`.

This is documented in the ZoneRecords guide and is intentional operator-facing
behavior, not silent accidental non-compliance.

---

## 7. Not Implemented / Out of Scope RFCs

The following RFCs (and related features) are not implemented directly in Foghorn at this time:

- **RFC 9230 – Oblivious DoH (ODoH)**
  - No ODoH support; DoH is implemented as standard RFC 8484 client/server.

- **RFC 9250 – DNS over QUIC (DoQ)**
  - No QUIC transport for DNS; only UDP, TCP, DoT, and DoH are supported.

- **Full RFC 7873 DNS Cookie authentication**
  - No server-secret cookie generation/validation as an anti-forgery feature;
    only cache-safe COOKIE strip/rebind is implemented (see §3.2).

- **True incremental IXFR client/server deltas (RFC 1995/5936 IXFR)**
  - IXFR queries are answered with full-zone AXFR-style transfers; no IXFR pull client.

- **General-purpose TSIG on ordinary recursive QUERY traffic (RFC 2845)**
  - TSIG is focused on AXFR/IXFR/UPDATE/NOTIFY paths.

Other newer or specialized DNS-related RFCs not listed above should be assumed
**not implemented** unless clearly documented in the code or configuration.

---

## 8. Practical Takeaways

- For typical stub resolver usage over UDP/TCP/DoT/DoH, Foghorn behaves like a standards-compliant caching resolver with policy hooks.
- Negative and referral caching follow RFC 2308 semantics for SOA/NS-based TTLs.
- DNSSEC is best used in **passthrough/upstream-validated** mode for production comfort; local validation exists but remains experimental.
- EDE is on by default for clearer policy/upstream diagnostics; full DNSSEC EDE coverage is still limited.
- ECS is trust-gated in forward mode and bypasses shared cache when it affects answers.
- COOKIE options are handled safely across cache hits but are not a full cookie-auth deployment.
- ZoneRecords can act as a limited authoritative edge: static/BIND sources, AXFR hydrate/refresh (startup + poll + NOTIFY-driven), optional DNS UPDATE with journals, outbound NOTIFY, and AXFR/IXFR serving over TCP/DoT with TSIG and allowlists.
- IXFR remains full-zone transfer style; there is no incremental IXFR client.
- Leading `*` wildcards in ZoneRecords are intentionally broader than RFC 4592.
- ODoH and DoQ remain out of scope.

---

## 9. Configuring ZoneRecords AXFR (client + server)

The `ZoneRecords` plugin can consume static records from:

- custom pipe-delimited files (`file_paths` / `file_path`),
- RFC 1035-style BIND zone files (`bind_paths`), and
- inline `records` entries,

and, when enabled, can also merge in data from upstream AXFR upstreams at startup and on later refresh cycles (reload timing, polling, and NOTIFY).

Source precedence (highest → lowest):

1. inline `records`
2. `axfr_zones`
3. `file_paths`
4. `bind_paths`

UPDATE-managed RRsets then override static sources for the same owner at query time.

### 9.1 Hybrid zonefile + AXFR workflow

A common deployment looks like this:

- Seed zones from local BIND-style files for `example.com` and friends.
- At startup (and optionally on poll/NOTIFY/reload), perform AXFR from one or more authoritative upstreams.
- Overlay transferred RRsets according to source precedence.
- Finally, apply any inline `records` overrides (and any DNS UPDATE journal state).

Example plugin entry (YAML):

```yaml
plugins:
  - id: example-zones
    type: zone_records
    config:
      bind_paths:
        - /etc/foghorn/zones/example.com.zone
        - /etc/foghorn/zones/example.net.zone
      # Optional: additional inline records in the custom pipe-delimited format
      records:
        - "example.com|TXT|300|managed by foghorn"

      # AXFR-backed zones; loaded during setup and refreshable later.
      axfr_zones:
        - zone: example.com
          minimum_reload_time: 30
          poll_interval_seconds: 300
          upstreams:
            - host: 192.0.2.10   # primary upstream
              port: 53
              timeout_ms: 5000   # shared connect/read timeout
              tsig:
                name: axfr-key.example.
                secret: BASE64_TSIG_SECRET==
                algorithm: hmac-sha256
            - host: 192.0.2.11   # secondary master (fallback)
              port: 53
        - zone: example.net
          upstreams:
            - host: 2001:db8::53
              port: 53
              timeout_ms: 8000

      # Static outbound NOTIFY targets (not auto-learned from AXFR clients)
      axfr_notify:
        - host: 192.0.2.50
          port: 53
          transport: tcp
```

Semantics:

- For each `axfr_zones` entry:
  - `zone` is the apex (with or without a trailing dot; it is normalized internally).
  - `upstreams` is a list of upstreams. Each upstream supports:
    - `host` (required): IPv4/IPv6 address or hostname,
    - `port` (optional): defaults to 53 for TCP and 853 for DoT in typical deployments,
    - `timeout_ms` (optional): shared connect/read timeout in milliseconds (default 5000),
    - `transport` (optional): `tcp` (default) or `dot` (DNS-over-TLS),
    - `server_name` (optional, DoT only): TLS SNI / verification name,
    - `verify` (optional, DoT only): whether to verify TLS certificates (default true),
    - `ca_file` (optional, DoT only): path to a CA bundle,
    - `tsig` (optional): `{name, secret, algorithm}` for AXFR request signing and response validation.
  - Refresh controls include `minimum_reload_time`, `poll_interval_seconds`,
    transfer size caps, retry/backoff, and public/private upstream gates.
- On `ZoneRecords.setup()` / reload:
  - Configured file and BIND sources are loaded.
  - AXFR is attempted for each configured zone when timing/backoff allow (first successful upstream wins).
  - Transferred RRsets are merged using documented precedence.
  - Inline `records` and UPDATE journal state apply as documented.
- Watchdog/polling continue to watch local files; AXFR refresh is separate
  (startup, reload timing, optional poll interval, inbound NOTIFY).

DoT example:

```yaml
plugins:
  - id: example-zones-dot
    type: zone_records
    config:
      axfr_zones:
        - zone: example.com
          upstreams:
            - host: 192.0.2.10
              port: 53
              transport: tcp
            - host: 2001:db8::1
              port: 853
              transport: dot
              server_name: axfr.example.com
              verify: true
              ca_file: /etc/ssl/certs/ca-bundle.crt
```

### 9.2 DNSSEC for Synthetic Zones

ZoneRecords can serve DNSSEC-signed records for synthetic zones when:

1. The zone data includes pre-generated DNSKEY and RRSIG records (via `bind_paths` or inline `records`), **or** `dnssec_signing` auto-signing is enabled.
2. The client query includes EDNS(0) with DO=1.

To sign a zone offline, use the provided helper script:

```bash
python scripts/generate_zone_dnssec.py \
  --zone example.com. \
  --input zones/example.com.zone \
  --output zones/example.com.signed.zone \
  --keys-dir keys/
```

The script:

- Generates KSK/ZSK keypairs (ECDSAP256SHA256 by default).
- Signs all RRsets with RRSIG records.
- Outputs DS records for parent delegation.

Once signed, configure `bind_paths` to point at the signed zone file. When
clients request DNSSEC, ZoneRecords automatically includes RRSIG and DNSKEY
records in responses.

Optional auto-signing:

```yaml
dnssec_signing:
  enabled: true
  keys_dir: ./keys
  algorithm: ECDSAP256SHA256
  generate: maybe   # yes | no | maybe
  validity_days: 30
  nsec3:
    salt: '-'
    iterations: 10
```

**Limitations:**

- Negative-proof completeness depends on signing mode/data; treat NSEC/NSEC3 coverage as partial unless you verify zone contents.
- Foghorn does not validate its own ZoneRecords responses as a recursive validator substitute.
- Re-run offline signing (or rely on auto-signing reload behavior) when zone data changes.

### 9.3 AXFR with DNSSEC policy hints

The `allow_no_dnssec` option controls AXFR acceptance messaging/policy for unsigned or incomplete DNSSEC zones:

```yaml
axfr_zones:
  - zone: secure.example
    allow_no_dnssec: false   # Prefer/require DNSSEC-complete transfers
    upstreams:
      - host: 192.0.2.10
  - zone: legacy.example
    allow_no_dnssec: true    # Accept transfers even without DNSSEC (default)
    upstreams:
      - host: 192.0.2.20
```

Foghorn classifies each AXFR-backed zone as `dnssec_state=present|partial|none`
and logs warnings when DNSKEY/RRSIG data is missing or incomplete, especially
when `allow_no_dnssec` is `false`. Treat hard-fail behavior as evolving; verify
current runtime behavior if you rely on reject-on-unsigned semantics.

### 9.4 DNS UPDATE (RFC 2136) quick pointer

```yaml
plugins:
  - id: zone-with-dynamic-updates
    type: zone_records
    config:
      dns_update:
        enabled: true
        zones:
          - zone: example.com
            tsig:
              keys:
                - name: "key.example.com."
                  algorithm: "hmac-sha256"
                  secret: "base64-secret"
```

Full key map, persistence/replication/security defaults, and auth notes:
`docs/plugins/resolve/zone_update.md`.

### 9.5 Limitations

- IXFR is served as a full AXFR-style transfer (no deltas yet); no IXFR client.
- AXFR TSIG is supported for both:
  - upstream AXFR client transfers via `axfr_zones[*].upstreams[*].tsig`, and
  - downstream AXFR/IXFR serving via nested `server.axfr.tsig` (legacy `tsig_keys` still accepted).
- AXFR/IXFR server role is available for ZoneRecords-authoritative zones over TCP/DoT.
  Use `server.axfr` hardening controls (`allow_clients`, `max_zone_rrs`,
  `max_concurrent_transfers`, optional per-client rate limit and transfer pacing)
  to constrain exposure and transfer load.
- Outbound NOTIFY targets are configured explicitly (`axfr_notify`); they are not learned from AXFR clients.
- DNS UPDATE authorization on the active path is TSIG-based (PSK schema fields are not currently enforced for request auth).

This document should be updated whenever Foghorn's DNS behavior meaningfully
changes with respect to any of the listed RFCs.
