from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol

"""Iterative recursive resolver core for Foghorn.

Inputs:
  - Public APIs documented on individual classes and functions.

Outputs:
  - Resolve DNS queries iteratively starting from root hints (once implemented).

Brief:
  This module is the nucleus for making Foghorn a full recursive resolver.
  It defines the types and interfaces used by the iterative engine and
  provides a `resolve_iterative` entrypoint that can be wired into
  `resolve_query_bytes` and `DNSUDPHandler.handle`.

  The initial version is a skeleton that focuses on API shape and is safe to
  import; the main resolution loop will be filled in incrementally under
  tests.
"""


@dataclass(frozen=True)
class AuthorityEndpoint:
    """Authority server endpoint used during iterative resolution.

    Inputs:
      - name: Owner name of the NS record (e.g. 'a.root-servers.net.').
      - host: IP address or hostname to contact.
      - port: UDP/TCP port (53 by default).
      - transport: Transport identifier ('udp', 'tcp', 'dot', or 'doh').

    Outputs:
      - Immutable description of an authority endpoint for the resolver.
    """

    name: str
    host: str
    port: int = 53
    transport: str = "udp"


@dataclass(frozen=True)
class TraceHop:
    """Single step in the recursive resolution trace.

    Inputs:
      - qname: Query name at this step.
      - qtype: Query type at this step.
      - authority: Authority endpoint used (or None for cache/local steps).
      - rcode: DNS RCODE integer (or None on pure transport errors/timeouts).
      - step: Short label for the kind of step ('cache_hit', 'root',
        'referral', 'answer', 'cname', 'error', etc.).
      - detail: Optional freeform detail string.

    Outputs:
      - Immutable record for debugging and tests.
    """

    qname: str
    qtype: int
    authority: Optional[AuthorityEndpoint]
    rcode: Optional[int]
    step: str
    detail: str = ""


@dataclass
class RecursiveTrace:
    """End-to-end trace for a single recursive resolution.

    Inputs:
      - hops: Ordered list of TraceHop entries recorded during resolution.
      - final_rcode: Final DNS RCODE integer, or None on internal error.
      - from_cache: True if the answer was entirely satisfied from cache.
      - exceeded_budget: True if time or depth budget was exhausted.
      - error: Optional internal error string (for diagnostics only).
      - security: Optional DNSSEC classification string ('secure', 'insecure',
        'indeterminate', or 'bogus').

    Outputs:
      - Mutable structure that callers and tests can inspect.
    """

    hops: list[TraceHop]
    final_rcode: Optional[int] = None
    from_cache: bool = False
    exceeded_budget: bool = False
    error: Optional[str] = None
    security: Optional[str] = None


@dataclass(frozen=True)
class ResolverConfig:
    """Configuration for a single recursive resolution.

    Inputs:
      - dnssec_mode: 'ignore', 'passthrough', or 'validate'.
      - edns_udp_payload: EDNS UDP payload size to advertise.
      - timeout_ms: Total end-to-end budget for this query in milliseconds.
      - per_try_timeout_ms: Default per-authority attempt timeout.
      - max_depth: Maximum number of resolution steps or CNAME hops.
      - now_ms: Optional callable that returns current time in milliseconds;
        useful for tests to control time.

    Outputs:
      - Immutable config snapshot used by resolve_iterative.
    """

    dnssec_mode: str
    edns_udp_payload: int
    timeout_ms: int
    per_try_timeout_ms: int
    max_depth: int
    now_ms: Optional[Callable[[], int]] = None


@dataclass(frozen=True)
class AnswerEntry:
    """Cached final answer for a (qname, qtype) pair.

    Inputs:
      - wire: Complete DNS response message suitable for clients.
      - rcode: DNS RCODE integer for the response.
      - expires_at_ms: Absolute expiry time in milliseconds since epoch.

    Outputs:
      - Immutable cache entry for client-visible answers.
    """

    wire: bytes
    rcode: int
    expires_at_ms: int


@dataclass(frozen=True)
class NegativeEntry:
    """Cached negative result (NXDOMAIN or NODATA) for (qname, qtype).

    Inputs:
      - rcode: DNS RCODE (typically NXDOMAIN or NOERROR for NODATA).
      - soa_owner: Owner name of the SOA used to derive TTL.
      - expires_at_ms: Absolute expiry time in milliseconds since epoch.

    Outputs:
      - Immutable cache entry describing a negative outcome.
    """

    rcode: int
    soa_owner: str
    expires_at_ms: int


@dataclass(frozen=True)
class RRsetKey:
    """Key for RRset-level cache entries.

    Inputs:
      - name: Owner name of the RRset.
      - rrtype: Numeric RR type.
      - rrclass: Numeric RR class (default IN=1).
      - validated: Optional DNSSEC validation flag (True, False, or None
        for insecure/unvalidated).

    Outputs:
      - Immutable key used to look up RRsetEntry values.
    """

    name: str
    rrtype: int
    rrclass: int = 1
    validated: Optional[bool] = None


@dataclass(frozen=True)
class RRsetEntry:
    """Cached RRset used for infra and DNSSEC data.

    Inputs:
      - rrset_wire: Encoded RRset representation (e.g. minimal DNS message
        or concatenated RRs) understood by the recursive resolver.
      - expires_at_ms: Absolute expiry time in milliseconds since epoch.

    Outputs:
      - Immutable cache entry for NS, glue, DNSKEY, DS, SOA, etc.
    """

    rrset_wire: bytes
    expires_at_ms: int


@dataclass(frozen=True)
class TrustAnchor:
    """DNSSEC trust anchor describing a single key or DS.

    Inputs:
      - owner: Owner name of the anchor (typically '.' for the root).
      - key_tag: Numeric key tag for the DNSKEY this anchor refers to.
      - algorithm: DNSKEY algorithm number.
      - digest_type: DS digest type (for DS-based anchors), or 0 if unused.
      - digest: Raw digest bytes for DS-based anchors, or b'' if unused.

    Outputs:
      - Immutable description of a single configured trust anchor.
    """

    owner: str
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes


@dataclass(frozen=True)
class ValidationResult:
    """Final DNSSEC classification for one recursive response.

    Inputs:
      - status: 'secure', 'insecure', 'indeterminate', or 'bogus'.
      - reason: Short human-readable reason for diagnostics and tests.

    Outputs:
      - Lightweight decision used to set AD or map to SERVFAIL.
    """

    status: str
    reason: str = ""


# Snapshot of configured trust anchors. The initial implementation leaves this
# empty; concrete root KSK/DS values will be wired in alongside the validation
# pipeline.
DEFAULT_TRUST_ANCHORS: tuple[TrustAnchor, ...] = ()


def _decode_rrset(entry: RRsetEntry) -> "DNSRecord":
    """Brief: Parse an RRsetEntry.rrset_wire into a DNSRecord.

    Inputs:
      - entry: RRsetEntry instance whose rrset_wire contains a DNS message.

    Outputs:
      - DNSRecord parsed from rrset_wire; callers are expected to filter RRsets
        of interest (DNSKEY, DS, etc.) from its sections.
    """

    from dnslib import DNSRecord  # local import

    return DNSRecord.parse(entry.rrset_wire)


def _dnskey_to_ds_digest(dnskey_rr, digest_type: int) -> tuple[int, bytes] | None:
    """Brief: Compute key tag and DS digest for a DNSKEY RR.

    Inputs:
      - dnskey_rr: DNSKEY RR object (dnslib RR with rtype=DNSKEY).
      - digest_type: DS digest type (1=SHA1, 2=SHA256, others ignored for now).

    Outputs:
      - (key_tag, digest_bytes) when the digest_type is supported; otherwise
        None.

    Notes:
      - This helper does not validate algorithms beyond basic digest support;
        callers must ensure the DNSKEY algorithm is acceptable for their
        security policy.
    """

    import hashlib
    from dnslib import QTYPE

    if getattr(dnskey_rr, "rtype", None) != QTYPE.DNSKEY:
        return None

    try:
        owner_name = dnskey_rr.rname
        rdata = dnskey_rr.rdata
        flags = int(getattr(rdata, "flags", 0))
        protocol = int(getattr(rdata, "protocol", 0))
        algorithm = int(getattr(rdata, "algorithm", 0))
        key_bytes = bytes(getattr(rdata, "key", b""))
    except Exception:
        return None

    # Key tag calculation from RFC 4034 Appendix B.
    try:
        rdata_wire = (
            bytes([flags >> 8 & 0xFF, flags & 0xFF, protocol, algorithm]) + key_bytes
        )
    except Exception:
        return None

    acc = 0
    for i, byte in enumerate(rdata_wire):
        if i & 1:
            acc += byte
        else:
            acc += byte << 8
    acc += (acc >> 16) & 0xFFFF
    key_tag = acc & 0xFFFF

    # Digest over canonical owner name + DNSKEY RDATA, per RFC 4034 §5.1.4.
    try:
        # owner_name.label is a tuple of raw label bytes; convert to wire format
        # with length prefixes and a root terminator.
        labels = list(getattr(owner_name, "label", []) or [])
        owner_wire = b"".join(bytes([len(l)]) + bytes(l) for l in labels) + b"\x00"
        data = owner_wire + rdata_wire
    except Exception:
        return None

    if digest_type == 1:
        digest = hashlib.sha1(data).digest()
    elif digest_type == 2:
        digest = hashlib.sha256(data).digest()
    else:
        return None

    return key_tag, digest


def _match_ds_to_dnskey(ds_rrs: list, dnskey_rrs: list) -> list:
    """Brief: Return DNSKEY RRs that are consistent with at least one DS.

    Inputs:
      - ds_rrs: List of DS RRs from a parent zone.
      - dnskey_rrs: List of DNSKEY RRs from the child zone.

    Outputs:
      - List of DNSKEY RRs whose key_tag/algorithm/digest match at least one DS
        record when digests can be computed. DS entries with unsupported
        digest_type are ignored.
    """

    from dnslib import QTYPE

    matches: list = []
    if not ds_rrs or not dnskey_rrs:
        return matches

    for ds in ds_rrs:
        if getattr(ds, "rtype", None) != QTYPE.DS:
            continue
        try:
            ds_rdata = ds.rdata
            ds_key_tag = int(getattr(ds_rdata, "key_tag", 0))
            ds_alg = int(getattr(ds_rdata, "algorithm", 0))
            ds_digest_type = int(getattr(ds_rdata, "digest_type", 0))
            ds_digest = bytes(getattr(ds_rdata, "digest", b""))
        except Exception:
            continue

        for dnskey in dnskey_rrs:
            try:
                dnskey_rdata = dnskey.rdata
                alg = int(getattr(dnskey_rdata, "algorithm", 0))
            except Exception:
                continue

            if alg != ds_alg:
                continue

            computed = _dnskey_to_ds_digest(dnskey, ds_digest_type)
            if computed is None:
                continue
            key_tag, digest = computed
            if key_tag == ds_key_tag and digest == ds_digest:
                matches.append(dnskey)

    return matches


def _get_dnskey_rrs_from_cache(cache: RecursiveCache, zone: str) -> list:
    """Brief: Return DNSKEY RRs for a zone from the recursive RRset cache.

    Inputs:
      - cache: RecursiveCache instance.
      - zone: Owner name whose DNSKEY RRset should be retrieved.

    Outputs:
      - List of DNSKEY RR objects (may be empty when the RRset is absent).
    """

    from dnslib import QTYPE

    name = zone.rstrip(".")
    if not name:
        name = ""
    key = RRsetKey(name=name, rrtype=QTYPE.DNSKEY)
    entry = cache.lookup_rrset(key)
    if entry is None:
        return []
    try:
        rec = _decode_rrset(entry)
    except Exception:
        return []

    rrs = list(getattr(rec, "rr", []) or [])
    rrs.extend(getattr(rec, "auth", []) or [])
    return [rr for rr in rrs if getattr(rr, "rtype", None) == QTYPE.DNSKEY]


def _get_ds_rrs_from_cache(cache: RecursiveCache, zone: str) -> list:
    """Brief: Return DS RRs for a parent zone from the recursive RRset cache.

    Inputs:
      - cache: RecursiveCache instance.
      - zone: Owner name whose DS RRset should be retrieved.

    Outputs:
      - List of DS RR objects (may be empty when the RRset is absent).
    """

    from dnslib import QTYPE

    name = zone.rstrip(".")
    if not name:
        name = ""
    key = RRsetKey(name=name, rrtype=QTYPE.DS)
    entry = cache.lookup_rrset(key)
    if entry is None:
        return []
    try:
        rec = _decode_rrset(entry)
    except Exception:
        return []

    rrs = list(getattr(rec, "rr", []) or [])
    rrs.extend(getattr(rec, "auth", []) or [])
    return [rr for rr in rrs if getattr(rr, "rtype", None) == QTYPE.DS]


def _get_rrset_and_rrsigs_from_cache(
    cache: RecursiveCache, name: str, rrtype: int
) -> tuple[list, list]:
    """Brief: Return an RRset and its covering RRSIGs from the RRset cache.

    Inputs:
      - cache: RecursiveCache instance.
      - name: Owner name of the RRset.
      - rrtype: Numeric RR type of the RRset being requested.

    Outputs:
      - Tuple (rrs, rrsigs):
        * rrs: List of RRs with rtype == rrtype for the given owner.
        * rrsigs: List of RRSIG RRs whose owner matches and whose
          type_covered field equals rrtype.

    Notes:
      - This helper relies on the existing RRsetEntry layout that stores a full
        DNS message; RRSIGs are cached alongside their covered RRsets and are
        filtered out here for validation use.
    """

    from dnslib import QTYPE

    owner = name.rstrip(".")
    if not owner:
        owner = ""
    key = RRsetKey(name=owner, rrtype=rrtype)
    entry = cache.lookup_rrset(key)
    if entry is None:
        return [], []
    try:
        rec = _decode_rrset(entry)
    except Exception:
        return [], []

    all_rrs = list(getattr(rec, "rr", []) or [])
    all_rrs.extend(getattr(rec, "auth", []) or [])

    rr_owner = owner
    rrs = [
        rr
        for rr in all_rrs
        if getattr(rr, "rtype", None) == rrtype
        and str(getattr(rr, "rname", "")).rstrip(".") == rr_owner
    ]

    rrsigs: list = []
    for rr in all_rrs:
        if getattr(rr, "rtype", None) != QTYPE.RRSIG:
            continue
        try:
            # dnslib.RRSIG stores the covered type in the 'covered' attribute.
            covered = int(getattr(rr.rdata, "covered", 0))
        except Exception:
            continue
        if covered != rrtype:
            continue
        if str(getattr(rr, "rname", "")).rstrip(".") != rr_owner:
            continue
        rrsigs.append(rr)

    return rrs, rrsigs


def _build_validation_chain(zone: str, cache: RecursiveCache) -> list[tuple[str, list]]:
    """Brief: Build a simple DNSSEC validation chain from cached DNSKEY RRsets.

    Inputs:
      - zone: Answer zone name (presentation format).
      - cache: RecursiveCache containing RRsetEntry values.

    Outputs:
      - List of (zone_name, dnskey_rrs) tuples ordered from closest ancestor to
        furthest (e.g. child.example.com, example.com, com), including only
        zones for which a DNSKEY RRset is present in the cache.

    Notes:
      - This helper currently ignores DS records and does not perform any
        cryptographic checks; it is intended as a structural building block for
        the full validation pipeline.
    """

    chain: list[tuple[str, list]] = []
    name = zone.rstrip(".")
    if not name:
        return chain

    labels = name.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        dnskeys = _get_dnskey_rrs_from_cache(cache, candidate)
        if dnskeys:
            chain.append((candidate, dnskeys))
    return chain


class RecursiveCache(Protocol):
    """Protocol for the recursive resolver's internal cache.

    Inputs:
      - Methods operate on AnswerEntry, NegativeEntry, and RRsetEntry values.

    Outputs:
      - Cached data used only by the iterative engine; outer response caches
        like DNSUDPHandler.cache remain separate.
    """

    def lookup_answer(self, qname: str, qtype: int) -> Optional[AnswerEntry]:
        """Return cached positive answer, or None if not found or expired.

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.

        Outputs:
          - AnswerEntry or None.
        """

    def store_answer(self, qname: str, qtype: int, entry: AnswerEntry) -> None:
        """Store a positive answer for (qname, qtype).

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.
          - entry: AnswerEntry to store.

        Outputs:
          - None
        """

    def lookup_negative(self, qname: str, qtype: int) -> Optional[NegativeEntry]:
        """Return cached negative result, or None if not found or expired.

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.

        Outputs:
          - NegativeEntry or None.
        """

    def store_negative(self, qname: str, qtype: int, entry: NegativeEntry) -> None:
        """Store a negative result for (qname, qtype).

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.
          - entry: NegativeEntry to store.

        Outputs:
          - None
        """

    def lookup_rrset(self, key: RRsetKey) -> Optional[RRsetEntry]:
        """Return cached RRset for the given key, or None.

        Inputs:
          - key: RRsetKey identifying the desired RRset.

        Outputs:
          - RRsetEntry or None.
        """

    def store_rrset(self, key: RRsetKey, entry: RRsetEntry) -> None:
        """Store an RRset for authority or DNSSEC use.

        Inputs:
          - key: RRsetKey for the RRset.
          - entry: RRsetEntry to store.

        Outputs:
          - None
        """


class TransportFacade(Protocol):
    """Protocol for sending DNS queries to a single authority endpoint.

    Inputs:
      - authority: AuthorityEndpoint to contact.
      - wire_query: Wire-format DNS query message.
      - timeout_ms: Per-attempt timeout in milliseconds.

    Outputs:
      - Tuple (response_wire, error):
        * response_wire: bytes or None on timeout/transport failure.
        * error: None on success or a short string such as 'timeout',
          'network_error', or 'bad_response'.
    """

    def query(
        self,
        authority: AuthorityEndpoint,
        wire_query: bytes,
        *,
        timeout_ms: int,
    ) -> tuple[Optional[bytes], Optional[str]]:
        """Send a DNS query to one authority and return response/error.

        Inputs:
          - authority: AuthorityEndpoint instance.
          - wire_query: Wire-format DNS query.
          - timeout_ms: Attempt timeout in milliseconds.

        Outputs:
          - (response_wire, error) as described in the class docstring.
        """


# Snapshot of the IANA root hints. This list is intentionally static; if root
# server addresses change, this constant should be updated in a dedicated
# change.
ROOT_HINTS: tuple[AuthorityEndpoint, ...] = (
    AuthorityEndpoint(name="a.root-servers.net.", host="198.41.0.4"),
    AuthorityEndpoint(name="a.root-servers.net.", host="2001:503:ba3e::2:30"),
    AuthorityEndpoint(name="b.root-servers.net.", host="199.9.14.201"),
    AuthorityEndpoint(name="b.root-servers.net.", host="2001:500:200::b"),
    AuthorityEndpoint(name="c.root-servers.net.", host="192.33.4.12"),
    AuthorityEndpoint(name="c.root-servers.net.", host="2001:500:2::c"),
    AuthorityEndpoint(name="d.root-servers.net.", host="199.7.91.13"),
    AuthorityEndpoint(name="d.root-servers.net.", host="2001:500:2d::d"),
    AuthorityEndpoint(name="e.root-servers.net.", host="192.203.230.10"),
    AuthorityEndpoint(name="e.root-servers.net.", host="2001:500:a8::e"),
    AuthorityEndpoint(name="f.root-servers.net.", host="192.5.5.241"),
    AuthorityEndpoint(name="f.root-servers.net.", host="2001:500:2f::f"),
    AuthorityEndpoint(name="g.root-servers.net.", host="192.112.36.4"),
    AuthorityEndpoint(name="g.root-servers.net.", host="2001:500:12::d0d"),
    AuthorityEndpoint(name="h.root-servers.net.", host="198.97.190.53"),
    AuthorityEndpoint(name="h.root-servers.net.", host="2001:500:1::53"),
    AuthorityEndpoint(name="i.root-servers.net.", host="192.36.148.17"),
    AuthorityEndpoint(name="i.root-servers.net.", host="2001:7fe::53"),
    AuthorityEndpoint(name="j.root-servers.net.", host="192.58.128.30"),
    AuthorityEndpoint(name="j.root-servers.net.", host="2001:503:c27::2:30"),
    AuthorityEndpoint(name="k.root-servers.net.", host="193.0.14.129"),
    AuthorityEndpoint(name="k.root-servers.net.", host="2001:7fd::1"),
    AuthorityEndpoint(name="l.root-servers.net.", host="199.7.83.42"),
    AuthorityEndpoint(name="l.root-servers.net.", host="2001:500:9f::42"),
    AuthorityEndpoint(name="m.root-servers.net.", host="202.12.27.33"),
    AuthorityEndpoint(name="m.root-servers.net.", host="2001:dc3::35"),
)


def get_root_servers() -> list[AuthorityEndpoint]:
    """Return the current list of root authority endpoints.

    Inputs:
      - None

    Outputs:
      - List of AuthorityEndpoint entries representing the root servers.

    Note:
      The list is a static in-module snapshot derived from IANA root hints
      and may need occasional updates as the root zone evolves.
    """

    return list(ROOT_HINTS)


def resolve_iterative(
    qname: str,
    qtype: int,
    *,
    cfg: ResolverConfig,
    cache: RecursiveCache,
    transports: TransportFacade,
    _resolving_ns: Optional[set[str]] = None,
) -> tuple[bytes, RecursiveTrace]:
    """Resolve a DNS query iteratively starting from root hints.

    Inputs:
      - qname: Query name as a presentation-format string.
      - qtype: Numeric query type (e.g. 1=A, 28=AAAA).
      - cfg: ResolverConfig instance controlling timeouts and DNSSEC/EDNS.
      - cache: RecursiveCache implementation used for RRset and answer reuse.
      - transports: TransportFacade used to contact authorities.
      - _resolving_ns: Internal set of NS hostnames currently being resolved
        as infrastructure lookups; callers should not pass this explicitly.

    Inputs:
      - qname: Query name as a presentation-format string.
      - qtype: Numeric query type (e.g. 1=A, 28=AAAA).
      - cfg: ResolverConfig instance controlling timeouts and DNSSEC/EDNS.
      - cache: RecursiveCache implementation used for RRset and answer reuse.
      - transports: TransportFacade used to contact authorities.

    Outputs:
      - (wire, trace):
        * wire: Wire-format DNS response suitable to send to a client.
        * trace: RecursiveTrace describing the path taken.

    Brief:
      Initial implementation focuses on a safe, testable happy path:
      - Answer/negative cache fast path.
      - Single-hop query to a root authority returned by get_root_servers().
      - Synthesizes SERVFAIL when no root hints or transport errors occur.

      The algorithm will be extended to full RFC 1034/1035 recursion in
      subsequent steps.
    """

    # Delayed import to avoid circular dependencies until integration phase.
    from dnslib import QTYPE, RCODE, DNSRecord

    trace = RecursiveTrace(hops=[])

    # Shared set guarding against re-entrant NS address resolution across nested
    # resolve_iterative calls within a single top-level query.
    if _resolving_ns is None:
        resolving_ns: set[str] = set()
    else:
        resolving_ns = _resolving_ns

    # Helper to obtain a wall clock in milliseconds; allows tests to inject
    # a deterministic clock via cfg.now_ms.
    def _now_ms() -> int:
        if cfg.now_ms is not None:
            return int(cfg.now_ms())
        import time as _time  # local import

        return int(_time.time() * 1000)

    def _make_servfail(
        detail: str, *, authority: AuthorityEndpoint | None = None
    ) -> tuple[bytes, RecursiveTrace]:
        """Brief: Build a SERVFAIL response and record an error hop.

        Inputs:
          - detail: Short description of why SERVFAIL was generated.
          - authority: Optional AuthorityEndpoint associated with the error.

        Outputs:
          - (wire, trace) with trace.final_rcode set to SERVFAIL.
        """

        # Use QTYPE.get to tolerate integer qtype values and always build a
        # valid question for dnslib. This avoids nested failures in error
        # handling paths when callers pass numeric types.
        qtype_for_question = QTYPE.get(qtype, qtype)
        q_local = DNSRecord.question(qname, qtype_for_question)
        r_local = q_local.reply()
        r_local.header.rcode = RCODE.SERVFAIL
        trace.final_rcode = RCODE.SERVFAIL
        trace.error = detail
        trace.hops.append(
            TraceHop(
                qname=qname,
                qtype=qtype,
                authority=authority,
                rcode=RCODE.SERVFAIL,
                step="error",
                detail=detail,
            )
        )
        return r_local.pack(), trace

    def _resolve_ns_addresses(ns_name: str) -> list[str]:
        """Brief: Resolve A/AAAA addresses for an NS hostname via recursion.

        Inputs:
          - ns_name: Nameserver hostname whose addresses should be resolved.

        Outputs:
          - List of IPv4/IPv6 string addresses discovered for the NS name.

        Notes:
          - This issues recursive lookups using the same engine with a reduced
            depth and timeout budget so that infrastructure lookups cannot
            exhaust the entire client query budget.
          - A small in-function guard prevents re-entrant resolution of the same
            NS name from causing unbounded recursion when every reply is a
            glue-less referral to that name.
        """

        ns_key = ns_name.rstrip(".").lower()
        if ns_key in resolving_ns:
            # Already resolving this NS name higher in the stack; avoid
            # recursing again and rely on depth/timeout limits in the main
            # resolution loop instead.
            return []

        # Impose a small per-query cap on the number of distinct NS hostnames
        # being resolved to guard against pathological glue-less delegation
        # trees. Once this soft budget is exceeded, further NS address lookups
        # are skipped and the main resolution loop's depth/timeout budgets are
        # relied upon instead.
        if len(resolving_ns) >= 16:
            return []

        resolving_ns.add(ns_key)
        try:
            # Derive a smaller budget for infrastructure lookups so they cannot
            # consume the entire query time; fall back to at least 1 ms and
            # respect the remaining top-level budget when one is configured.
            remaining_ms: int
            if cfg.timeout_ms > 0:
                # Use the remaining top-level budget as an upper bound.
                elapsed = _now_ms() - start_ms
                remaining_ms = max(1, cfg.timeout_ms - max(0, elapsed))
            else:
                # When no global timeout is configured, bound infra lookups by
                # the per-try timeout or a small default window.
                base = cfg.per_try_timeout_ms if cfg.per_try_timeout_ms > 0 else 1000
                remaining_ms = max(1, int(base))

            # Cap infra lookups to at most one quarter of the original timeout,
            # while never exceeding the remaining top-level budget.
            base_cap = cfg.timeout_ms // 4 or cfg.timeout_ms or remaining_ms
            nested_timeout = max(1, min(int(base_cap), int(remaining_ms)))

            nested_per_try = (
                cfg.per_try_timeout_ms if cfg.per_try_timeout_ms > 0 else nested_timeout
            )
            nested_cfg = ResolverConfig(
                dnssec_mode=cfg.dnssec_mode,
                edns_udp_payload=cfg.edns_udp_payload,
                timeout_ms=nested_timeout,
                per_try_timeout_ms=min(nested_per_try, nested_timeout),
                max_depth=max(1, cfg.max_depth // 2),
                now_ms=cfg.now_ms,
            )

            addrs: list[str] = []
            for addr_qtype in (QTYPE.A, QTYPE.AAAA):
                try:
                    wire, _trace = resolve_iterative(
                        ns_name,
                        addr_qtype,
                        cfg=nested_cfg,
                        cache=cache,
                        transports=transports,
                        _resolving_ns=resolving_ns,
                    )
                except RecursionError:
                    continue
                try:
                    msg = DNSRecord.parse(wire)
                except Exception:
                    continue
                for rr in msg.rr or []:
                    if rr.rtype == addr_qtype:
                        addrs.append(str(rr.rdata))

            return addrs
        finally:
            resolving_ns.discard(ns_key)

    def _lookup_cached_authorities_for_qname(qname_str: str) -> list[AuthorityEndpoint]:
        """Brief: Return authorities derived from cached NS RRsets, if any.

        Inputs:
          - qname_str: Query name to resolve.

        Outputs:
          - List of AuthorityEndpoint entries built from the most specific
            cached NS RRsets, or an empty list if no suitable entries exist.

        Notes:
          - Only in-bailiwick NS names and glue (A/AAAA) are used when
            constructing AuthorityEndpoint entries. Out-of-bailiwick data is
            ignored to reduce the impact of malicious or misconfigured
            authority sections.
        """

        now = _now_ms()
        labels = qname_str.rstrip(".").split(".")
        if len(labels) < 2:
            return []

        # Walk from closest enclosing domain outward, e.g. for
        # www.example.com -> example.com, com.
        for i in range(1, len(labels)):
            zone = ".".join(labels[i:])
            key = RRsetKey(name=zone, rrtype=QTYPE.NS)
            entry = cache.lookup_rrset(key)
            if entry is None or entry.expires_at_ms <= now:
                continue
            try:
                cached = DNSRecord.parse(entry.rrset_wire)
            except Exception:
                continue

            auth_rrs = getattr(cached, "auth", []) or []
            ns_rrs = [rr for rr in auth_rrs if rr.rtype == QTYPE.NS]
            if not ns_rrs:
                continue

            # Collect in-bailiwick A/AAAA glue from the additional section and
            # build candidate authorities for all nameservers in the RRset.
            additional_rrs = getattr(cached, "ar", []) or []
            glue_by_name: dict[str, list[str]] = {}
            for rr in additional_rrs:
                if rr.rtype not in (QTYPE.A, QTYPE.AAAA):
                    continue
                name_str = str(rr.rname).rstrip(".")
                # Only accept glue that is in-bailiwick for the delegated zone.
                if not name_str.endswith(zone):
                    continue
                glue_by_name.setdefault(name_str, []).append(str(rr.rdata))

            authorities: list[AuthorityEndpoint] = []
            for ns_rr in ns_rrs:
                try:
                    child_name = str(getattr(ns_rr.rdata, "label", ns_rr.rdata)).rstrip(
                        "."
                    )
                except Exception:
                    child_name = str(ns_rr.rdata).rstrip(".")

                # Only use NS names that are in-bailiwick for the zone.
                if not child_name.endswith(zone):
                    continue

                hosts = glue_by_name.get(child_name)

                if hosts:
                    for host_ip in hosts:
                        authorities.append(
                            AuthorityEndpoint(
                                name=str(ns_rr.rname),
                                host=host_ip,
                                port=53,
                                transport="udp",
                            )
                        )
                else:
                    # Fall back to the NS hostname itself and rely on the
                    # underlying networking stack for address resolution.
                    authorities.append(
                        AuthorityEndpoint(
                            name=str(ns_rr.rname),
                            host=child_name,
                            port=53,
                            transport="udp",
                        )
                    )

            if authorities:
                return authorities

        return []

    try:
        original_qname = qname
        current_qname = qname
        cname_depth = 0
        start_ms = _now_ms()

        # Normalize DNSSEC mode once per query for EDNS/DO handling.
        dnssec_mode = str(cfg.dnssec_mode).lower()

        def _maybe_cache_dnssec_rrsets(parsed: "DNSRecord", now_ms: int) -> None:
            """Best-effort caching of DNSSEC-related RRsets for validation.

            Inputs:
              - parsed: Upstream DNSRecord response.
              - now_ms: Current wall clock in milliseconds.

            Outputs:
              - None; stores DNSKEY/DS RRsets in the RecursiveCache when TTLs
                are positive, using validated=None to indicate unvalidated data.
            """

            from dnslib import QTYPE as _QTYPE  # local import

            auth_rrs = getattr(parsed, "auth", []) or []
            answer_rrs = getattr(parsed, "rr", []) or []

            def _store_rrset(owner: str, rrtype: int, rrs: list) -> None:
                ttl_candidates: list[int] = []
                for rr in rrs:
                    ttl_val = getattr(rr, "ttl", None)
                    if isinstance(ttl_val, (int, float)):
                        ttl_candidates.append(int(ttl_val))
                ttl = min(ttl_candidates) if ttl_candidates else 0
                if ttl <= 0:
                    return
                entry = RRsetEntry(
                    rrset_wire=parsed.pack(),
                    expires_at_ms=now_ms + ttl * 1000,
                )
                key = RRsetKey(
                    name=str(owner).rstrip("."),
                    rrtype=rrtype,
                    validated=None,
                )
                cache.store_rrset(key, entry)

            dnskey_rrs = [
                rr for rr in (answer_rrs + auth_rrs) if rr.rtype == _QTYPE.DNSKEY
            ]
            if dnskey_rrs:
                owner = str(dnskey_rrs[0].rname)
                _store_rrset(owner, _QTYPE.DNSKEY, dnskey_rrs)

            ds_rrs = [rr for rr in auth_rrs if rr.rtype == _QTYPE.DS]
            if ds_rrs:
                owner = str(ds_rrs[0].rname)
                _store_rrset(owner, _QTYPE.DS, ds_rrs)

        def _dnssec_validate_final_response(
            parsed: "DNSRecord",
        ) -> ValidationResult:
            """Minimal structural DNSSEC validation for dnssec_mode='validate'.

            Inputs:
              - parsed: Final upstream DNSRecord chosen as the answer.

            Outputs:
              - ValidationResult describing the DNSSEC classification.

            Notes:
              - This implementation performs a lightweight DS/DNSKEY chain
                inspection using cached RRsets and configured trust anchors but
                does not yet verify RRSIGs or set AD on the wire.
              - Results are exposed via RecursiveTrace.security only; bogus
                classifications are *not* enforced as SERVFAIL at this stage.
            """

            del parsed  # currently unused; reserved for future RRSIG checks

            if not DEFAULT_TRUST_ANCHORS:
                return ValidationResult(
                    status="indeterminate",
                    reason="no_trust_anchors",
                )

            # Approximate the answer zone using the original qname and the
            # cached DNSKEY RRsets we already have.
            chain = _build_validation_chain(original_qname, cache)
            if not chain:
                return ValidationResult(
                    status="indeterminate",
                    reason="no_dnskey_rrsets_in_chain",
                )

            # Mark zones that have an associated trust anchor as validated in the
            # cache and remember which zones are anchored for DS/DNSKEY walking.
            validated_any = False
            zones_in_chain = {zone.rstrip(".") for (zone, _dnskeys) in chain}
            anchor_zones: list[str] = []

            for anchor in DEFAULT_TRUST_ANCHORS:
                zone = anchor.owner.rstrip(".")
                if not zone or zone not in zones_in_chain:
                    continue

                base_key = RRsetKey(name=zone, rrtype=QTYPE.DNSKEY)
                base_entry = cache.lookup_rrset(base_key)
                if base_entry is None:
                    continue

                validated_key = RRsetKey(
                    name=zone,
                    rrtype=QTYPE.DNSKEY,
                    validated=True,
                )
                if cache.lookup_rrset(validated_key) is None:
                    cache.store_rrset(
                        validated_key,
                        RRsetEntry(
                            rrset_wire=base_entry.rrset_wire,
                            expires_at_ms=base_entry.expires_at_ms,
                        ),
                    )

                anchor_zones.append(zone)
                validated_any = True

            if not validated_any:
                return ValidationResult(
                    status="indeterminate",
                    reason="no_trust_anchors_in_chain",
                )

            # Prepare maps for walking the chain from each anchor down towards
            # the most-specific zone (closest to the original qname).
            zone_to_index: dict[str, int] = {}
            zone_to_dnskeys: dict[str, list] = {}
            for idx, (zone_name, dnskeys) in enumerate(chain):
                z = zone_name.rstrip(".")
                zone_to_index[z] = idx
                zone_to_dnskeys[z] = dnskeys

            any_bogus = False
            any_secure_path = False
            any_insecure = False

            for anchor_zone in anchor_zones:
                anchor_idx = zone_to_index.get(anchor_zone)
                if anchor_idx is None:
                    continue

                # Start from the anchor itself and walk "down" the chain towards
                # the child-most zone (index 0), checking DS/DNSKEY links.
                status_for_anchor = "secure"
                i = anchor_idx - 1
                while i >= 0:
                    child_zone = chain[i][0].rstrip(".")
                    child_dnskeys = zone_to_dnskeys.get(child_zone) or []
                    ds_rrs = _get_ds_rrs_from_cache(cache, child_zone)
                    if not ds_rrs:
                        # Unsigned or insecure delegation at this cut; once an
                        # insecure link is hit, the remainder of the subtree is
                        # treated as insecure.
                        status_for_anchor = "insecure"
                        break

                    matched = _match_ds_to_dnskey(ds_rrs, child_dnskeys)
                    if not matched:
                        status_for_anchor = "bogus"
                        break

                    i -= 1

                if status_for_anchor == "bogus":
                    any_bogus = True
                elif status_for_anchor == "insecure":
                    any_insecure = True
                else:
                    any_secure_path = True

            if any_bogus:
                return ValidationResult(
                    status="bogus",
                    reason="ds_mismatch_in_chain",
                )

            if any_secure_path:
                return ValidationResult(
                    status="secure",
                    reason="validated_trust_anchors_and_ds_chain",
                )

            # At least one anchor was present in the chain, but all reachable
            # paths encountered an insecure delegation (no DS RRset).
            if any_insecure:
                return ValidationResult(
                    status="insecure",
                    reason="insecure_delegation_in_chain",
                )

            # Fallback: anchors existed but did not align with any usable chain
            # entries; treat as indeterminate for now.
            return ValidationResult(
                status="indeterminate",
                reason="anchors_not_applicable_to_chain",
            )

        # 1. Cache fast path for positive answers.
        cached_answer = cache.lookup_answer(original_qname, qtype)
        # The initial implementation treats any present AnswerEntry as valid.
        # Expiry handling will be wired in alongside a consistent time base for
        # the recursive cache. For now this keeps the behavior simple and
        # test-friendly.
        if cached_answer is not None:
            trace.from_cache = True
            trace.final_rcode = cached_answer.rcode
            trace.hops.append(
                TraceHop(
                    qname=original_qname,
                    qtype=qtype,
                    authority=None,
                    rcode=cached_answer.rcode,
                    step="cache_hit",
                    detail="answer_cache",
                )
            )
            return cached_answer.wire, trace

        # 2. Cache fast path for negative answers.
        cached_neg = cache.lookup_negative(original_qname, qtype)
        if cached_neg is not None and cached_neg.expires_at_ms > _now_ms():
            q_local = DNSRecord.question(original_qname, qtype)
            r_local = q_local.reply()
            r_local.header.rcode = cached_neg.rcode
            trace.from_cache = True
            trace.final_rcode = cached_neg.rcode
            trace.hops.append(
                TraceHop(
                    qname=qname,
                    qtype=qtype,
                    authority=None,
                    rcode=cached_neg.rcode,
                    step="cache_hit",
                    detail="negative_cache",
                )
            )
            return r_local.pack(), trace

        # 3. Try using cached NS+glue RRsets as an authority shortcut before
        #    consulting root hints.
        authorities = _lookup_cached_authorities_for_qname(current_qname)

        # 5. If no cached authority, seed from root hints.
        if not authorities:
            roots = get_root_servers()
            if not roots:
                return _make_servfail("no_root_servers")
            authorities = roots

        failed_authorities: set[AuthorityEndpoint] = set()

        # 6. Main referral/alias loop: repeatedly query available authorities
        #    until we obtain a non-referral/non-alias answer or run out of
        #    budget or options.
        depth = 0
        while True:
            # Enforce overall time budget for the query.
            now_ms = _now_ms()
            if cfg.timeout_ms > 0 and now_ms - start_ms >= cfg.timeout_ms:
                trace.exceeded_budget = True
                return _make_servfail("timeout_budget_exhausted")

            if depth > cfg.max_depth:
                trace.exceeded_budget = True
                # When depth is exceeded, we have likely followed too many
                # delegations or encountered a loop; treat as SERVFAIL.
                return _make_servfail("max_depth_exceeded")

            # Select the next authority that has not yet failed for this
            # resolution attempt.
            candidate_authorities = [
                a for a in authorities if a not in failed_authorities
            ]
            if not candidate_authorities:
                trace.exceeded_budget = True
                return _make_servfail("no_authorities_available")

            authority = candidate_authorities[0]

            # Build the current query and attach an EDNS(0) OPT record that
            # reflects the configured DNSSEC mode. When dnssec_mode is
            # 'passthrough' or 'validate', the DO bit (0x8000) is set so that
            # upstream authorities may return DNSSEC records and/or AD=1.
            q = DNSRecord.question(current_qname, QTYPE.get(qtype, qtype))
            try:
                mode = dnssec_mode
                if mode in ("ignore", "passthrough", "validate"):
                    from dnslib import EDNS0, RR as _RR  # local import

                    flags = 0x8000 if mode in ("passthrough", "validate") else 0
                    opt_idx = None
                    for idx, rr in enumerate(getattr(q, "ar", []) or []):
                        if rr.rtype == QTYPE.OPT:
                            opt_idx = idx
                            break
                    opt_rr = _RR(
                        rname=".",
                        rtype=QTYPE.OPT,
                        rclass=int(cfg.edns_udp_payload or 1232),
                        ttl=0,
                        rdata=EDNS0(flags=flags),
                    )
                    if opt_idx is None:
                        q.add_ar(opt_rr)
                    else:
                        q.ar[opt_idx] = opt_rr
            except Exception:  # pragma: no cover - defensive
                # EDNS is a best-effort enhancement; failures must not break
                # query processing.
                pass

            wire_query = q.pack()

            # Derive a per-attempt timeout from the remaining budget.
            remaining_ms = (
                cfg.timeout_ms - (now_ms - start_ms)
                if cfg.timeout_ms > 0
                else cfg.per_try_timeout_ms
            )
            if remaining_ms <= 0:
                trace.exceeded_budget = True
                return _make_servfail("timeout_budget_exhausted")
            per_try_timeout = (
                cfg.per_try_timeout_ms if cfg.per_try_timeout_ms > 0 else remaining_ms
            )
            per_try_timeout = max(1, min(int(per_try_timeout), int(remaining_ms)))

            response_wire, error = transports.query(
                authority,
                wire_query,
                timeout_ms=per_try_timeout,
            )

            if response_wire is None or error is not None:
                detail = error or "transport_failure"
                failed_authorities.add(authority)
                trace.hops.append(
                    TraceHop(
                        qname=current_qname,
                        qtype=qtype,
                        authority=authority,
                        rcode=None,
                        step="error",
                        detail=detail,
                    )
                )
                # Try the next authority, if any.
                continue

            # Parse upstream response to obtain rcode; on parse error, mark this
            # authority as failed and try others.
            try:
                parsed = DNSRecord.parse(response_wire)
                rcode = parsed.header.rcode
                # Opportunistically cache DNSSEC RRsets when validation is
                # enabled. This does not change the answer behavior and simply
                # prepares data for a future validation pipeline.
                if dnssec_mode == "validate":
                    _maybe_cache_dnssec_rrsets(parsed, now_ms=_now_ms())
            except Exception:
                failed_authorities.add(authority)
                trace.hops.append(
                    TraceHop(
                        qname=current_qname,
                        qtype=qtype,
                        authority=authority,
                        rcode=None,
                        step="error",
                        detail="bad_response",
                    )
                )
                continue

            auth_rrs = getattr(parsed, "auth", []) or []
            has_ns = any(rr.rtype == QTYPE.NS for rr in auth_rrs)

            # Referral: NOERROR with no answers but NS in the authority
            # section. Cache NS+glue, update the authority set, and continue.
            if rcode == RCODE.NOERROR and not parsed.rr and has_ns:
                ns_rrs = [rr for rr in auth_rrs if rr.rtype == QTYPE.NS]
                ns_rr0 = ns_rrs[0]

                # Bailiwick check for the delegated owner name: only follow
                # referrals whose owner name is a suffix of the current qname.
                # This guards against misdirected referrals that attempt to
                # delegate queries for one subtree (e.g. example.com) to an
                # unrelated zone (e.g. attacker.net).
                try:
                    delegated_owner = str(ns_rr0.rname).rstrip(".")
                except Exception:
                    delegated_owner = ""
                if delegated_owner and not current_qname.rstrip(".").endswith(
                    delegated_owner
                ):
                    failed_authorities.add(authority)
                    trace.hops.append(
                        TraceHop(
                            qname=current_qname,
                            qtype=qtype,
                            authority=authority,
                            rcode=rcode,
                            step="error",
                            detail="referral_out_of_bailiwick",
                        )
                    )
                    continue

                # Store NS RRset (with glue in additional section) into the
                # RecursiveCache so that subsequent queries can skip earlier
                # delegation points.
                ttl_candidates: list[int] = []
                for rr in auth_rrs:
                    if rr.rtype == QTYPE.NS:
                        ttl_val = getattr(rr, "ttl", None)
                        if isinstance(ttl_val, (int, float)):
                            ttl_candidates.append(int(ttl_val))
                if ttl_candidates:
                    ns_ttl = max(1, min(ttl_candidates))
                    expires_at = _now_ms() + ns_ttl * 1000
                    ns_key = RRsetKey(
                        name=str(ns_rr0.rname).rstrip("."), rrtype=QTYPE.NS
                    )
                    cache.store_rrset(
                        ns_key,
                        RRsetEntry(rrset_wire=response_wire, expires_at_ms=expires_at),
                    )

                # Build a set of child authorities from all NS records and any
                # available A/AAAA glue in the additional section.
                additional_rrs = getattr(parsed, "ar", []) or []
                glue_by_name: dict[str, list[str]] = {}
                for rr in additional_rrs:
                    if rr.rtype not in (QTYPE.A, QTYPE.AAAA):
                        continue
                    name_str = str(rr.rname).rstrip(".")
                    glue_by_name.setdefault(name_str, []).append(str(rr.rdata))

                child_authorities: list[AuthorityEndpoint] = []
                for ns_rr in ns_rrs:
                    try:
                        child_name = str(
                            getattr(ns_rr.rdata, "label", ns_rr.rdata)
                        ).rstrip(".")
                    except Exception:
                        child_name = str(ns_rr.rdata).rstrip(".")

                    # Only consider NS names that are in-bailiwick for the
                    # delegation owner (ns_rr.rname).
                    try:
                        owner_name = str(ns_rr.rname).rstrip(".")
                    except Exception:
                        owner_name = ""
                    if owner_name and not child_name.endswith(owner_name):
                        continue

                    hosts = glue_by_name.get(child_name)

                    if hosts:
                        for host_ip in hosts:
                            child_authorities.append(
                                AuthorityEndpoint(
                                    name=str(ns_rr.rname),
                                    host=host_ip,
                                    port=authority.port,
                                    transport=authority.transport,
                                )
                            )
                    else:
                        # When no in-bailiwick A/AAAA glue is available, attempt
                        # to resolve the NS hostname's addresses via the
                        # recursive engine itself using a reduced budget.
                        resolved_addrs = _resolve_ns_addresses(child_name)
                        for addr in resolved_addrs:
                            child_authorities.append(
                                AuthorityEndpoint(
                                    name=str(ns_rr.rname),
                                    host=addr,
                                    port=authority.port,
                                    transport=authority.transport,
                                )
                            )

                        # As a conservative fallback when address lookups fail,
                        # retain the NS hostname itself so that environments
                        # with working system resolvers can still make
                        # progress.
                        if not resolved_addrs:
                            child_authorities.append(
                                AuthorityEndpoint(
                                    name=str(ns_rr.rname),
                                    host=child_name,
                                    port=authority.port,
                                    transport=authority.transport,
                                )
                            )

                if not child_authorities:
                    failed_authorities.add(authority)
                    trace.hops.append(
                        TraceHop(
                            qname=current_qname,
                            qtype=qtype,
                            authority=authority,
                            rcode=rcode,
                            step="error",
                            detail="no_child_authorities",
                        )
                    )
                    continue

                trace.hops.append(
                    TraceHop(
                        qname=current_qname,
                        qtype=qtype,
                        authority=authority,
                        rcode=rcode,
                        step="referral",
                        detail="delegation",
                    )
                )

                authorities = child_authorities
                failed_authorities.clear()
                depth += 1
                continue

            # CNAME handling: if we received an alias without a final RRset of
            # the requested type, follow the first CNAME target using the same
            # authority set.
            answer_rrs = parsed.rr or []
            if rcode == RCODE.NOERROR and answer_rrs and qtype != QTYPE.CNAME:
                cname_rrs = [rr for rr in answer_rrs if rr.rtype == QTYPE.CNAME]
                final_rrs = [rr for rr in answer_rrs if rr.rtype == qtype]
                if cname_rrs and not final_rrs:
                    cname_depth += 1
                    if cname_depth > cfg.max_depth:
                        trace.exceeded_budget = True
                        return _make_servfail(
                            "cname_depth_exceeded", authority=authority
                        )

                    cname_rr = cname_rrs[0]
                    try:
                        target_name = str(cname_rr.rdata).rstrip(".")
                    except Exception:
                        target_name = str(cname_rr.rdata)

                    trace.hops.append(
                        TraceHop(
                            qname=current_qname,
                            qtype=qtype,
                            authority=authority,
                            rcode=rcode,
                            step="cname",
                            detail=f"follow {target_name}",
                        )
                    )

                    current_qname = target_name
                    depth += 1
                    failed_authorities.clear()
                    # Re-evaluate authorities for the new name: prefer cached
                    # NS+glue, then fall back to roots.
                    authorities = _lookup_cached_authorities_for_qname(current_qname)
                    if not authorities:
                        roots = get_root_servers()
                        if not roots:
                            return _make_servfail("no_root_servers")
                        authorities = roots
                    continue

            # Non-referral/non-alias path: treat authority's reply as final.
            trace.final_rcode = rcode
            trace.hops.append(
                TraceHop(
                    qname=current_qname,
                    qtype=qtype,
                    authority=authority,
                    rcode=rcode,
                    step="answer",
                    detail="final_answer",
                )
            )

            # Optional DNSSEC validation hook for dnssec_mode='validate'. The
            # initial implementation is a stub which classifies all responses
            # as 'indeterminate' so that behavior matches 'passthrough'.
            if dnssec_mode == "validate":
                validation = _dnssec_validate_final_response(parsed)
                trace.security = validation.status
                # Bogus/secure classifications are currently observational only;
                # AD/SERVFAIL behavior will be wired in once the full validation
                # pipeline (including RRSIG checks) is in place.

            # Cache final positive and negative answers for (original_qname, qtype)
            # so subsequent queries can be satisfied from the recursive cache.
            try:
                now_store = _now_ms()
                # Positive answers: NOERROR with at least one answer RR.
                if rcode == RCODE.NOERROR and parsed.rr:
                    ttls = [
                        int(getattr(rr, "ttl", 0))
                        for rr in parsed.rr
                        if isinstance(getattr(rr, "ttl", None), (int, float))
                    ]
                    ttl = min(ttls) if ttls else 0
                    if ttl > 0:
                        cache.store_answer(
                            original_qname,
                            qtype,
                            AnswerEntry(
                                wire=response_wire,
                                rcode=rcode,
                                expires_at_ms=now_store + ttl * 1000,
                            ),
                        )
                else:
                    # Negative caching for NXDOMAIN or NODATA responses with an
                    # SOA in the authority section.
                    auth_rrs = getattr(parsed, "auth", None) or []
                    soa_rrs = [rr for rr in auth_rrs if rr.rtype == QTYPE.SOA]
                    if soa_rrs and (
                        rcode == RCODE.NXDOMAIN
                        or (rcode == RCODE.NOERROR and not parsed.rr)
                    ):
                        # Only trust SOA owners that are in-bailiwick for the
                        # original query name. This prevents NXDOMAIN/NODATA
                        # responses that carry an SOA for an unrelated zone
                        # (e.g. attacker.net while answering under example.com)
                        # from poisoning the negative cache.
                        try:
                            soa_owner = str(soa_rrs[0].rname).rstrip(".")
                        except Exception:
                            soa_owner = ""
                        qname_owner = original_qname.rstrip(".")
                        if soa_owner and not qname_owner.endswith(soa_owner):
                            # Skip negative caching for out-of-bailiwick SOA.
                            pass
                        else:
                            ttl_candidates: list[int] = []
                            for rr in soa_rrs:
                                try:
                                    ttl_val = getattr(rr, "ttl", None)
                                    if isinstance(ttl_val, (int, float)):
                                        ttl_candidates.append(int(ttl_val))
                                    rdata = getattr(rr, "rdata", None)
                                    minimum = getattr(rdata, "minttl", None) or getattr(
                                        rdata, "minimum", None
                                    )
                                    if isinstance(minimum, (int, float)):
                                        ttl_candidates.append(int(minimum))
                                except Exception:
                                    continue
                            neg_ttl = min(ttl_candidates) if ttl_candidates else 0
                            if neg_ttl > 0:
                                cache.store_negative(
                                    original_qname,
                                    qtype,
                                    NegativeEntry(
                                        rcode=rcode,
                                        soa_owner=soa_owner,
                                        expires_at_ms=now_store + neg_ttl * 1000,
                                    ),
                                )
            except Exception:
                # Cache population is best-effort; failures must not break query
                # processing.
                pass

            return response_wire, trace

    except Exception as exc:  # pragma: no cover - defensive fallback
        # In an extreme error case, try to build a bare SERVFAIL with a new ID.
        try:
            wire, err_trace = _make_servfail(f"unhandled_exception: {exc!s}")
            return wire, err_trace
        except Exception:
            # As a last resort, return an empty message and mark error.
            trace.final_rcode = None
            trace.error = f"fatal_exception: {exc!s}"
            return b"", trace
