# Foghorn DNS RFC Compliance

This document summarizes how Foghorn’s behavior maps onto major DNS-related RFCs. It focuses on what is implemented today, what is close/partial, and what is explicitly out of scope.

## RFC Summary Table

|       RFC | Short Title                                     | Status                               |
|-----------+-------------------------------------------------+--------------------------------------|
|      1034 | DNS Concepts and Facilities                     | Implemented (core behavior)          |
|      1035 | DNS Implementation and Specification            | Implemented (core behavior)          |
|      2308 | Negative Caching of DNS Queries                 | Implemented (negative/NS caching)    |
|      5011 | Automated Updates of DNS Security Trust Anchors | Implemented                          |
|      7766 | DNS over TCP                                    | Implemented                          |
|      7858 | DNS over TLS (DoT)                              | Implemented                          |
|      7958 | DNSSEC Trust Anchor Publication for the Root    | Implemented (root trust anchor)      |
|      8484 | DNS over HTTPS (DoH)                            | Implemented                          |
| 4033–4035 | DNSSEC protocol/records/validation              | Experimental / partial               |
|      6891 | Extension Mechanisms for DNS (EDNS(0))          | Partially implemented (minimal EDNS) |
|      7873 | Domain Name System (DNS) Cookies                | Not implemented                      |
|      8914 | Extended DNS Errors                             | Not implemented                      |
|      5936 | DNS Zone Transfer Protocol (AXFR/IXFR)          | Not implemented / out of scope       |
|      9230 | Oblivious DNS over HTTPS (ODoH)                 | Not implemented / out of scope       |
|      9250 | DNS over QUIC (DoQ)                             | Not implemented / out of scope       |

Status legend:

- **Implemented** – Actively used on the wire and tested; behavior is meant to be compatible with the RFC for the covered use cases.
- **Implemented (core behavior)** – Normal query/response flows follow the RFCs; Foghorn does not aim to implement every corner case (e.g., full authoritative features or zone transfers).
- **Partially implemented** – Only the subset needed for Foghorn’s current feature set is present.
- **Experimental / partial** – Feature is available but marked experimental and may not cover all RFC scenarios.
- **Not implemented / out of scope** – No explicit support; queries may still be forwarded opaquely by upstreams.

---

## 1. Core DNS (RFC 1034, RFC 1035)

Foghorn is a caching, policy-aware DNS forwarder. For standard query/response flows:

- Uses `dnslib` for parsing and building DNS messages in line with RFC 1034/1035.
- Preserves the DNS ID across responses.
- Handles typical RR types (A, AAAA, CNAME, TXT, etc.) and standard RCODEs.
- Acts primarily as a caching **forwarding** resolver, with optional authoritative-style answers provided by the ZoneRecords plugin (static records from local files). It does **not** implement general-purpose AXFR/IXFR zone transfer logic.

In practice, for normal stub-resolver traffic, Foghorn behaves like a conventional RFC 1034/1035-compliant caching resolver.

---

## 2. Transports

### 2.1 DNS over UDP and TCP (RFC 1035, RFC 7766)

- **UDP:**
  - Standard UDP DNS listener for queries.
  - Uses the same parsing, caching, plugin, and statistics pipeline as other transports.
- **TCP (RFC 7766):**
  - Implements length-prefixed DNS messages over TCP.
  - Uses connection pooling for upstream TCP resolvers.
  - Supports persistent connections with one in-flight query per connection at a time.

Foghorn follows the protocol requirements in RFC 7766 for framing and basic connection handling; some of the more detailed operational guidance (e.g., highly tuned limits under extreme load) is handled in a straightforward but not elaborate way.

### 2.2 DNS over TLS (DoT) – RFC 7858

- Downstream DoT server:
  - Asyncio-based TLS listener that accepts length-prefixed DNS queries over TLS.
  - Uses TLS 1.2+ with configurable certificate/key paths.
- Upstream DoT client:
  - Uses an `ssl.SSLContext` with a minimum TLS version of 1.2.
  - Supports SNI (`server_name`) and certificate verification controls per upstream.

Behavior is designed to match RFC 7858’s framing and TLS requirements for typical resolver use.

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

Foghorn implements a minimal subset of EDNS(0):

- Adds or replaces a single OPT record in outgoing queries when DNSSEC is enabled.
- Uses a configurable `edns_udp_payload` (default 1232) to set the advertised UDP payload size.
- Sets the DO bit when `dnssec.mode` requires it (see DNSSEC section below).
- Does **not** implement advanced EDNS options (cookies, NSID, ECS, extended errors, etc.).

For most modern resolvers and authoritative servers, this minimalist EDNS(0) support is sufficient to enable larger responses and DNSSEC records.

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

In this mode Foghorn does not directly implement all of RFC 4033–4035 itself; instead it relies on an upstream that does, and uses the AD bit and DNSSEC data to guide behavior and statistics.

### 4.3 Local validation (experimental) – RFCs 4033–4035 and 7958

When `dnssec.mode: validate` and `dnssec.validation: local` are set, Foghorn performs its own validation using `dnspython`:

- Uses a baked-in root DNSKEY trust anchor derived from the IANA root anchors (per RFC 7958) as the starting trust anchor.
- Probes for DNSKEY and DS records up the hierarchy to locate the zone apex for a given query.
- Validates DS/DNSKEY chains from the root to the apex.
- Locates the answer RRset and its RRSIG and validates signatures using the apex DNSKEY set.
- Classifies responses as `secure`, `insecure`, `indeterminate`, or `bogus`.
- Can convert locally-classified `bogus` answers into SERVFAIL.

This mode is explicitly marked **experimental** and does not claim complete coverage of all DNSSEC edge cases (e.g., complex rollover timing, every algorithm combination, or unusual record types). It is suitable for experimentation and modest setups but not yet a full replacement for mature validators like Unbound/BIND.

---

## 5. Not Implemented / Out of Scope RFCs

The following RFCs (and related features) are not implemented directly in Foghorn at this time:

- **RFC 5936 – DNS Zone Transfer Protocol (AXFR/IXFR)**
  - No explicit AXFR/IXFR server or client.
  - Foghorn can serve static records via the ZoneRecords plugin but does not perform zone transfers.

- **RFC 7873 – DNS Cookies**
  - No DNS Cookies support on either downstream or upstream sides.

- **RFC 8914 – Extended DNS Errors (EDE)**
  - No generation or parsing of extended error codes; responses may still carry EDE from upstreams, but Foghorn treats them as opaque.

- **RFC 9230 – Oblivious DoH (ODoH)**
  - No ODoH support; DoH is implemented as standard RFC 8484 client/server.

- **RFC 9250 – DNS over QUIC (DoQ)**
  - No QUIC transport for DNS; only UDP, TCP, DoT, and DoH are supported.

Other newer or specialized DNS-related RFCs not listed above should be assumed **not implemented** unless clearly documented in the code or configuration.

---

## 6. Practical Takeaways

- For typical stub resolver usage over UDP/TCP/DoT/DoH, Foghorn behaves like a standards-compliant caching resolver with policy hooks.
- Negative and referral caching follow RFC 2308 semantics for SOA/NS-based TTLs.
- DNSSEC is best used in **passthrough/upstream-validated** mode for now; local validation exists but is experimental.
- Advanced DNS extensions (cookies, extended errors, DoQ, ODoH, zone transfers) are out of scope at present.

This document should be updated whenever Foghorn’s DNS behavior meaningfully changes with respect to any of the listed RFCs.
