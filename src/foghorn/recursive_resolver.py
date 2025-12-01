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

    Outputs:
      - Mutable structure that callers and tests can inspect.
    """

    hops: list[TraceHop]
    final_rcode: Optional[int] = None
    from_cache: bool = False
    exceeded_budget: bool = False
    error: Optional[str] = None


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
) -> tuple[bytes, RecursiveTrace]:
    """Resolve a DNS query iteratively starting from root hints.

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
        """

        # Derive a smaller budget for infrastructure lookups so they cannot
        # consume the entire query time; fall back to at least 1 ms.
        nested_timeout = max(1, int(cfg.timeout_ms // 4 or cfg.timeout_ms))
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

    def _lookup_cached_authorities_for_qname(qname_str: str) -> list[AuthorityEndpoint]:
        """Brief: Return authorities derived from cached NS RRsets, if any.

        Inputs:
          - qname_str: Query name to resolve.

        Outputs:
          - List of AuthorityEndpoint entries built from the most specific
            cached NS RRsets, or an empty list if no suitable entries exist.
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
                glue_by_name.setdefault(name_str, []).append(str(rr.rdata))

            authorities: list[AuthorityEndpoint] = []
            for ns_rr in ns_rrs:
                try:
                    child_name = str(getattr(ns_rr.rdata, "label", ns_rr.rdata)).rstrip(
                        "."
                    )
                except Exception:
                    child_name = str(ns_rr.rdata).rstrip(".")

                hosts = glue_by_name.get(child_name)

                # For now, avoid recursive NS address lookups when glue is
                # missing. Falling back to the NS hostname directly keeps the
                # resolver from recursing indefinitely when every reply is a
                # referral with no glue.
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

            # Build the current query. EDNS/DO handling will be added when the
            # resolver is wired into DNSUDPHandler's EDNS helpers.
            q = DNSRecord.question(current_qname, QTYPE.get(qtype, qtype))
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

                    hosts = glue_by_name.get(child_name)

                    # Avoid recursive NS address lookups when there is no glue.
                    # This keeps purely-referral loops from recursing via
                    # _resolve_ns_addresses and ensures depth/time budgets are
                    # enforced in the main resolution loop instead.
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
                        # As a last resort, retain the NS hostname as the
                        # authority host and rely on the underlying stack.
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
                            soa_owner = str(soa_rrs[0].rname).rstrip(".")
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
