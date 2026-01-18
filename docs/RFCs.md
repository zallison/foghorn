# Foghorn DNS RFC Compliance

This document summarizes how Foghorn’s behavior maps onto major DNS-related RFCs. It focuses on what is implemented today, what is close/partial, and what is explicitly out of scope.

## RFC Summary Table

|       RFC | Short Title                                     | Status                                                   |
|-----------+-------------------------------------------------+----------------------------------------------------------|
|      1034 | DNS Concepts and Facilities                     | Implemented (core behavior)                              |
|      1035 | DNS Implementation and Specification            | Implemented (core behavior)                              |
|      2308 | Negative Caching of DNS Queries                 | Implemented                                              |
|      5011 | Automated Updates of DNS Security Trust Anchors | Implemented                                              |
|      7766 | DNS over TCP                                    | Implemented                                              |
|      7858 | DNS over TLS (DoT)                              | Implemented                                              |
|      7958 | DNSSEC Trust Anchor Publication for the Root    | Implemented                                              |
|      8484 | DNS over HTTPS (DoH)                            | Implemented                                              |
| 4033–4035 | DNSSEC protocol/records/validation              | Partially implemented                                    |
|      6891 | Extension Mechanisms for DNS (EDNS(0))          | Partially implemented                                    |
|      8914 | Extended DNS Errors                             | Partially implemented (EDE for policy/upstream failures) |
|      5936 | DNS Zone Transfer Protocol (AXFR/IXFR)          | Partially implemented (AXFR client + limited server)                      |
|      1996 | DNS NOTIFY                                      | Not implemented                                          |
|      2136 | Dynamic Updates in the DNS                      | Not implemented                                          |
|      2845 | Secret Key Transaction Authentication for DNS   | Not implemented                                          |
|      7873 | Domain Name System (DNS) Cookies                | Not implemented                                          |
|      9230 | Oblivious DNS over HTTPS (ODoH)                 | Not implemented / out of scope                           |
|      9250 | DNS over QUIC (DoQ)                             | Not implemented / out of scope                           |

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
  (static records from local files).

In practice, for normal stub-resolver traffic, Foghorn behaves like a conventional RFC 1034/1035-compliant caching resolver.

---

## 2. Transports

### 2.1 DNS over UDP and TCP (RFC 1035, RFC 7766)

- **UDP:**
  - Standard UDP DNS listener for queries.
  - Uses the same parsing, caching, plugin, and statistics pipeline as othefoghorn.servers.transports.
- **TCP (RFC 7766):**
  - Implements length-prefixed DNS messages over TCP.
  - Uses connection pooling for upstream TCP resolvers.
  - Supports persistent connections with one in-flight query per connection at a time.

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
typical resolver use.

### 2.3 DNS over HTTPS (DoH) – RFC 8484

- **Upstream DoH client:**
  - Supports both `POST` with `Content-Type: application/dns-message` and `GET` with `?dns=<base64url>`.
  - Uses base64url encoding **without padding** for the `dns` query parameter.
  - Validates HTTPS connections with configurable verification and CA bundle settings.
- **Downstream DoH server:**
  - Exposes `/dns-query` over HTTP/HTTPS using both FastAPI-based and threaded HTTP handlers.
  - Implements `GET /dns-query?dns=<base64url>` and `POST /dns-query` with `application/dns-message`.
  - Forwards wire-format DNS queries through the same resolver pipeline as UDP/TCP/DoT.

These code paths explicitly target RFC 8484 semantics for both client and server roles.

---

## 3. EDNS(0) and Negative Caching

### 3.1 EDNS(0) – RFC 6891 (Partial)

Foghorn implements a minimal but standards-aware subset of EDNS(0):

- Ensures there is exactly one OPT record in outgoing upstream queries in forward mode.
- Mirrors a client's EDNS version and advertised UDP payload size when present, clamped by a configurable `edns_udp_payload` (default 1232).
- When a client does **not** send EDNS, assumes the classic 512-byte UDP size and marks oversized responses as truncated (TC=1) to encourage TCP fallback.
- Sets the DO bit in EDNS flags when `dnssec.mode` requires it (`passthrough` / `validate`) and clears it in `ignore` mode, while preserving other EDNS flag bits.
- Does **not** implement advanced EDNS options (cookies, NSID, ECS, extended errors, etc.).

For most modern resolvers and authoritative servers, this EDNS(0) support is sufficient to enable larger responses and DNSSEC records, while remaining conservative for legacy non-EDNS clients.

### 3.2 Negative Caching – RFC 2308

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

### 4.3 Local validation (experimental) – RFCs 4033–4035 and 7958

When `dnssec.mode: validate` and `dnssec.validation: local` are set, Foghorn performs its own validation using `dnspython`:

- Uses a baked-in root DNSKEY trust anchor derived from the IANA root anchors (per RFC 7958) as the starting trust anchor.
- Probes for DNSKEY and DS records up the hierarchy to locate the zone apex for a given query.
- Validates DS/DNSKEY chains from the root to the apex.
- Locates the answer RRset and its RRSIG and validates signatures using the apex DNSKEY set.
- Classifies responses as `secure`, `insecure`, `indeterminate`, or `bogus`.
- Can convert locally-classified `bogus` answers into SERVFAIL.

This mode is explicitly marked **experimental** and does not claim complete
coverage of all DNSSEC edge cases (e.g., complex rollover timing, every
algorithm combination, or unusual record types). It is suitable for
experimentation and modest setups but not yet a full replacement for mature
validators like Unbound/BIND.

---

## 5. Not Implemented / Out of Scope RFCs

The following RFCs (and related features) are not implemented directly in Foghorn at this time:

- **RFC 5936 – DNS Zone Transfer Protocol (AXFR/IXFR)**
  - Foghorn implements a **limited AXFR/IXFR server** for zones backed by the
    `ZoneRecords` plugin over DNS-over-TCP and DoT. AXFR and IXFR queries for an
    authoritative apex are answered by streaming a full zone dump bounded by
    matching SOA records; IXFR is currently implemented as a full AXFR-style
    transfer (no deltas).
  - A limited AXFR **client** is available for the `ZoneRecords` plugin: when
	configured, it can perform a full TCP-based AXFR at startup for one or more
	zones and merge the transferred RRsets into the in-memory zone data
	alongside local zonefiles and inline records. There is no IXFR client support
	yet and no incremental refresh loop yet.

- **RFC 7873 – DNS Cookies**
  - No DNS Cookies support on either downstream or upstream sides.

- **RFC 1996 – DNS NOTIFY**
  - No DNS NOTIFY support; Foghorn does not act as a primary or secondary authoritative server that sends or processes NOTIFY messages.

- **RFC 2136 – Dynamic Updates in the DNS (DNS UPDATE)**
  - No DNS UPDATE (dynamic update) support. Zone data is loaded from static
	sources (files, BIND-style zones, inline records, and optional one-shot
	AXFR) and is not modified via UPDATE opcodes.

- **RFC 2845 – Secret Key Transaction Authentication for DNS (TSIG)**
  - No TSIG signing or verification for queries, responses, or zone
	transfers. AXFR client support in `ZoneRecords` operates without TSIG.

- **RFC 8914 – Extended DNS Errors**
-  - When `server.enable_ede` is true and the client advertises EDNS(0), Foghorn
   can attach RFC 8914 Extended DNS Error (EDE) options to certain synthetic
   responses (for example, policy denies, rate limits, and upstream failures)
   while leaving RCODE semantics unchanged. Upstream-provided EDE options are
   forwarded opaquely. Full DNSSEC-related EDE coverage is not implemented.

- **RFC 9230 – Oblivious DoH (ODoH)**
  - No ODoH support; DoH is implemented as standard RFC 8484 client/server.

- **RFC 9250 – DNS over QUIC (DoQ)**
  - No QUIC transport for DNS; only UDP, TCP, DoT, and DoH are supported.

Other newer or specialized DNS-related RFCs not listed above should be assumed
**not implemented** unless clearly documented in the code or configuration.

---

## 6. Practical Takeaways

- For typical stub resolver usage over UDP/TCP/DoT/DoH, Foghorn behaves like a standards-compliant caching resolver with policy hooks.
- Negative and referral caching follow RFC 2308 semantics for SOA/NS-based TTLs.
- DNSSEC is best used in **passthrough/upstream-validated** mode for now; local validation exists but is experimental.
- Advanced DNS extensions (cookies, extended errors, DoQ, ODoH) are out of scope at present.
- Zone transfers are supported in a **limited form**: the `ZoneRecords` plugin
  can optionally perform AXFR at startup to hydrate or refresh authoritative
  zones, and Foghorn can answer AXFR/IXFR queries for zones served by
  ZoneRecords over DNS-over-TCP and DoT. There is no IXFR client support yet
  and no dynamic NOTIFY/UPDATE-based zone maintenance.

---

## 7. Configuring ZoneRecords AXFR (client-only)

The `ZoneRecords` plugin can consume static records from:
- custom pipe-delimited files (`file_paths` / `file_path`),
- RFC 1035-style BIND zone files (`bind_paths`), and
- inline `records` entries,

and, when enabled, can also merge in data from upstream AXFR upstreams at startup.

### 7.1 Hybrid zonefile + AXFR workflow

A common deployment looks like this:

- Seed zones from local BIND-style files for `example.com` and friends.
- At startup, perform AXFR from one or more authoritative upstreams.
- Overlay transferred RRsets on top of the file-backed data.
- Finally, apply any inline `records` overrides.

Example plugin entry (YAML):

```yaml
plugins:
  - name: example-zones
	plugin: zone_records
	config:
	  bind_paths:
		- /etc/foghorn/zones/example.com.zone
		- /etc/foghorn/zones/example.net.zone

	  # Optional: additional inline records in the custom pipe-delimited format
	  records:
		- "example.com|TXT|300|managed by foghorn"

	  # Optional AXFR-backed zones; loaded **once** during startup.
  axfr_zones:
		- zone: example.com
		  upstreams:
			- host: 192.0.2.10   # primary upstream
			  port: 53
			  timeout_ms: 5000   # shared connect/read timeout
			- host: 192.0.2.11   # secondary master (fallback)
			  port: 53
		- zone: example.net
		  upstreams:
			- host: 2001:db8::53
			  port: 53
			  timeout_ms: 8000
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
	- `ca_file` (optional, DoT only): path to a CA bundle.
- On `ZoneRecords.setup()`:
  - All configured file and BIND sources are loaded first.
  - Then AXFR is attempted for each configured zone (first master that succeeds wins).
  - Transferred RRsets are merged into the same internal maps used for file/BIND/inline data.
  - Any inline `records` are applied last as overrides.
- AXFR is **only performed once** at startup; watchdog and polling reloads continue to watch local files only and do not re-transfer zones yet.

DoT example:

```yaml
plugins:
  - name: example-zones-dot
	plugin: zone_records
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

### 7.2 DNSSEC for Synthetic Zones

ZoneRecords can serve DNSSEC-signed records for synthetic zones when:

1. The zone data includes pre-generated DNSKEY and RRSIG records (via `bind_paths` or inline `records`).
2. The client query includes EDNS(0) with DO=1.

To sign a zone, use the provided helper script:

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

**Limitations:**
- NSEC/NSEC3 negative proofs are not generated.
- Foghorn does not validate its own ZoneRecords responses.
- Re-run the signing script when zone data changes.

### 7.3 AXFR with DNSSEC validation (future)

The `allow_no_dnssec` option controls AXFR acceptance for unsigned or DNSSEC-invalid zones:

```yaml
axfr_zones:
  - zone: secure.example
	allow_no_dnssec: false   # Reject transfers without valid DNSSEC
	upstreams:
	  - host: 192.0.2.10
  - zone: legacy.example
	allow_no_dnssec: true    # Accept transfers even without DNSSEC (default)
	upstreams:
	  - host: 192.0.2.20
```

When `allow_no_dnssec: false`, Foghorn will reject the transfer if DNSSEC
validation fails once this feature is fully implemented. Currently
`allow_no_dnssec` defaults to `true` and has no effect.

### 7.4 Limitations

- No IXFR, TSIG, or incremental refresh loop.
- No AXFR/IXFR server role; downstream clients cannot request zone transfers from Foghorn directly.

This document should be updated whenever Foghorn's DNS behavior meaningfully
changes with respect to any of the listed RFCs.
