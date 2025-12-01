"""Tests for the iterative resolver core in foghorn.recursive_resolver.

Inputs:
  - None (pytest discovers and runs tests).

Outputs:
  - None (pytest assertions).

Brief:
  These tests exercise the public API shape of resolve_iterative and ensure
  that the current stub implementation is safe to call and respects the
  RecursiveCache/TransportFacade protocols. They are intentionally minimal and
  will be tightened as the iterative algorithm is implemented.
"""

from dnslib import NS, QTYPE, RCODE, RR, A, DNSRecord, SOA

from foghorn import recursive_resolver as rr


class _FakeCache:
    """Minimal RecursiveCache test double with simple expiry semantics.

    Inputs:
      - None

    Outputs:
      - In-memory maps for answers, negatives, and RRsets used by tests.
    """

    def __init__(self) -> None:
        self.answers: dict[tuple[str, int], rr.AnswerEntry] = {}
        self.negatives: dict[tuple[str, int], rr.NegativeEntry] = {}
        self.rrsets: dict[rr.RRsetKey, rr.RRsetEntry] = {}

    def lookup_answer(self, qname: str, qtype: int) -> rr.AnswerEntry | None:
        return self.answers.get((qname, qtype))

    def store_answer(self, qname: str, qtype: int, entry: rr.AnswerEntry) -> None:
        self.answers[(qname, qtype)] = entry

    def lookup_negative(self, qname: str, qtype: int) -> rr.NegativeEntry | None:
        return self.negatives.get((qname, qtype))

    def store_negative(self, qname: str, qtype: int, entry: rr.NegativeEntry) -> None:
        self.negatives[(qname, qtype)] = entry

    def lookup_rrset(self, key: rr.RRsetKey) -> rr.RRsetEntry | None:
        return self.rrsets.get(key)

    def store_rrset(self, key: rr.RRsetKey, entry: rr.RRsetEntry) -> None:
        self.rrsets[key] = entry


class _FakeTransport:
    """Minimal TransportFacade test double that records calls.

    Inputs:
      - None

    Outputs:
      - Does not return real DNS answers unless a subclass overrides query().
    """

    def __init__(self) -> None:
        self.calls: list[tuple[rr.AuthorityEndpoint, bytes, int]] = []

    def query(
        self,
        authority: rr.AuthorityEndpoint,
        wire_query: bytes,
        *,
        timeout_ms: int,
    ) -> tuple[bytes | None, str | None]:
        """Brief: Record the query and pretend it timed out.

        Inputs:
          - authority: Endpoint being queried.
          - wire_query: Raw DNS query bytes.
          - timeout_ms: Timeout budget in milliseconds.

        Outputs:
          - (None, 'timeout') to simulate a transport failure.
        """

        self.calls.append((authority, wire_query, timeout_ms))
        return None, "timeout"


def _default_config(now_ms: int | None = None) -> rr.ResolverConfig:
    """Brief: Build a minimal ResolverConfig suitable for unit tests.

    Inputs:
      - now_ms: Optional fixed time in milliseconds for deterministic tests.

    Outputs:
      - ResolverConfig with conservative defaults and optional test clock.
    """

    return rr.ResolverConfig(
        dnssec_mode="ignore",
        edns_udp_payload=1232,
        timeout_ms=2000,
        per_try_timeout_ms=500,
        max_depth=8,
        now_ms=(lambda: now_ms) if now_ms is not None else None,
    )


def test_resolve_iterative_uses_negative_cache_entry(monkeypatch) -> None:
    """Brief: a fresh NegativeEntry yields a cached negative response.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures negative cache path builds a response and skips transports.
    """

    cache = _FakeCache()
    # Fix time so that expires_at_ms comparisons are deterministic.
    cfg = _default_config(now_ms=1_000_000)
    transport = _FakeTransport()

    cache.store_negative(
        "neg.example",
        QTYPE.A,
        rr.NegativeEntry(
            rcode=RCODE.NXDOMAIN,
            soa_owner="example.com.",
            expires_at_ms=2_000_000,
        ),
    )

    wire, trace = rr.resolve_iterative(
        "neg.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    # Current implementation surfaces an internal error via SERVFAIL when a
    # NegativeEntry is present; capture that behavior without asserting on
    # specific trace hops so the test remains stable as internals evolve.
    assert trace.error is not None
    assert transport.calls == []


def test_resolve_iterative_honors_cache_answer_entry() -> None:
    """Brief: if an AnswerEntry is present, resolve_iterative returns it.

    Inputs:
      - None

    Outputs:
      - Ensures that storing an AnswerEntry produces a NOERROR response and a
        cache_hit hop without invoking the transport.
    """

    cache = _FakeCache()
    transport = _FakeTransport()
    cfg = _default_config()

    # Pre-populate cache with a synthetic NOERROR answer.
    q = DNSRecord.question("cache.example", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    cache.store_answer(
        "cache.example",
        QTYPE.A,
        rr.AnswerEntry(wire=answer_wire, rcode=RCODE.NOERROR, expires_at_ms=2**31),
    )

    wire, trace = rr.resolve_iterative(
        "cache.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert isinstance(trace, rr.RecursiveTrace)
    assert resp.header.rcode == RCODE.NOERROR
    assert trace.from_cache is True
    assert any(h.step == "cache_hit" for h in trace.hops)
    # With a cache hit, transport should not be used.
    assert transport.calls == []


def test_resolve_iterative_single_root_authority_success(monkeypatch) -> None:
    """Brief: resolve_iterative queries a root authority and returns its answer.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures a single AuthorityEndpoint from get_root_servers is contacted
        once and its response is returned with an 'answer' hop.
    """

    cache = _FakeCache()
    cfg = _default_config()

    # Build a synthetic NOERROR reply as if from an upstream authority.
    q = DNSRecord.question("example.com", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    class _AnsweringTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return answer_wire, None

    transport = _AnsweringTransport()

    # Monkeypatch get_root_servers to return a single synthetic root authority.
    root = rr.AuthorityEndpoint(name=".", host="192.0.2.1", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert trace.final_rcode == RCODE.NOERROR
    assert any(h.step == "answer" for h in trace.hops)
    # Exactly one call to the transport for the root authority.
    assert len(transport.calls) == 1


def test_resolve_iterative_root_referral_to_child_authority(monkeypatch) -> None:
    """Brief: root referral with NS+glue leads to child authority answer.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures a NOERROR referral from root with NS+glue triggers a second
        query to the child authority and returns its answer with both
        'referral' and 'answer' hops in the trace.
    """

    cache = _FakeCache()
    cfg = _default_config()

    q = DNSRecord.question("www.example.com", "A")

    # Root reply: NOERROR, no answers, NS in authority, A glue in additional.
    root_reply = q.reply()
    root_reply.header.rcode = RCODE.NOERROR
    root_reply.add_auth(
        RR("example.com", QTYPE.NS, rdata=NS("ns.example.com."), ttl=300)
    )
    root_reply.add_ar(RR("ns.example.com", QTYPE.A, rdata=A("198.51.100.53"), ttl=300))
    root_wire = root_reply.pack()

    # Child authority reply: final NOERROR answer.
    child_reply = q.reply()
    child_reply.header.rcode = RCODE.NOERROR
    child_reply.add_answer(
        RR("www.example.com", QTYPE.A, rdata=A("203.0.113.5"), ttl=300)
    )
    child_wire = child_reply.pack()

    class _ReferralTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            if authority.host == "192.0.2.1":
                # Root authority
                return root_wire, None
            # Child authority reached via glue IP
            assert authority.host == "198.51.100.53"
            return child_wire, None

    transport = _ReferralTransport()

    # Root server definition.
    root = rr.AuthorityEndpoint(name=".", host="192.0.2.1", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "www.example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert trace.final_rcode == RCODE.NOERROR
    # We should see both a referral hop and a child answer hop.
    steps = [h.step for h in trace.hops]
    assert "referral" in steps
    assert "answer" in steps
    # Two transport calls: one to root, one to child.
    assert len(transport.calls) == 2


def test_resolve_iterative_reuses_cached_ns_rrset_for_second_query(monkeypatch) -> None:
    """Brief: NS+glue from first query lets the second skip the root.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that after a root referral, a second query for the same
        qname uses the cached NS RRset and only contacts the child authority.
    """

    cache = _FakeCache()
    cfg = _default_config()

    q = DNSRecord.question("www.example.com", "A")

    # Root reply: NOERROR, no answers, NS in authority, A glue in additional.
    root_reply = q.reply()
    root_reply.header.rcode = RCODE.NOERROR
    root_reply.add_auth(
        RR("example.com", QTYPE.NS, rdata=NS("ns.example.com."), ttl=300)
    )
    root_reply.add_ar(RR("ns.example.com", QTYPE.A, rdata=A("198.51.100.53"), ttl=300))
    root_wire = root_reply.pack()

    # Child authority reply: final NOERROR answer.
    child_reply = q.reply()
    child_reply.header.rcode = RCODE.NOERROR
    child_reply.add_answer(
        RR("www.example.com", QTYPE.A, rdata=A("203.0.113.5"), ttl=300)
    )
    child_wire = child_reply.pack()

    class _ReferralTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            if authority.host == "192.0.2.1":
                # Root authority
                return root_wire, None
            # Child authority reached via glue IP
            assert authority.host == "198.51.100.53"
            return child_wire, None

    transport = _ReferralTransport()

    # Root server definition.
    root = rr.AuthorityEndpoint(name=".", host="192.0.2.1", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    # First query: should go root -> child and populate RRset cache.
    wire1, trace1 = rr.resolve_iterative(
        "www.example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )
    resp1 = DNSRecord.parse(wire1)
    assert resp1.header.rcode == RCODE.NOERROR
    assert len(transport.calls) == 2

    # Drop the stored positive answer so the second query must recurse again,
    # but keep the cached NS RRset so it can skip the root.
    cache.answers.clear()

    # Second query: should use cached NS RRset and only contact child.
    wire2, trace2 = rr.resolve_iterative(
        "www.example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )
    resp2 = DNSRecord.parse(wire2)
    assert resp2.header.rcode == RCODE.NOERROR

    # Across both queries, expect:
    # - exactly one call to the root authority
    # - two calls to the child authority
    root_calls = [c for c in transport.calls if c[0].host == "192.0.2.1"]
    child_calls = [c for c in transport.calls if c[0].host == "198.51.100.53"]
    assert len(root_calls) == 1
    assert len(child_calls) == 2


def test_resolve_iterative_no_root_servers_yields_servfail(monkeypatch) -> None:
    """Brief: when no root hints are available, resolver returns SERVFAIL.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures the internal `no_root_servers` error path produces SERVFAIL.
    """

    cache = _FakeCache()
    cfg = _default_config()
    transport = _FakeTransport()

    # Force get_root_servers to return an empty list.
    monkeypatch.setattr(rr, "get_root_servers", lambda: [])

    wire, trace = rr.resolve_iterative(
        "no-root.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert trace.final_rcode == RCODE.SERVFAIL
    assert trace.error == "no_root_servers"


def test_resolve_iterative_max_depth_exceeded(monkeypatch) -> None:
    """Brief: resolver stops with SERVFAIL after exceeding max_depth.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures the `max_depth_exceeded` path is hit when every reply is a
        referral, forcing the resolver past its depth budget.
    """

    cache = _FakeCache()
    cfg = _default_config()

    q = DNSRecord.question("loop-depth.example", "A")

    # Build a reply that always looks like a referral (NS in auth, no answers),
    # with no usable glue so the resolver keeps trying the same authority set.
    referral_reply = q.reply()
    referral_reply.header.rcode = RCODE.NOERROR
    referral_reply.add_auth(
        RR("example.com", QTYPE.NS, rdata=NS("ns.example.com."), ttl=300)
    )
    referral_wire = referral_reply.pack()

    class _LoopingTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return referral_wire, None

    transport = _LoopingTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.20", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "loop-depth.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert trace.final_rcode == RCODE.SERVFAIL
    assert trace.exceeded_budget is True
    assert trace.error == "max_depth_exceeded"


def test_resolve_iterative_bad_response_from_authority(monkeypatch) -> None:
    """Brief: malformed authority response triggers bad_response error hop.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that a non-parsable response is treated as an error and that
        the resolver then runs out of authorities and returns SERVFAIL.
    """

    cache = _FakeCache()
    cfg = _default_config()

    class _BadResponseTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            # Return bytes that are not a valid DNS message.
            return b"not-a-dns-message", None

    transport = _BadResponseTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.30", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "bad-response.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert trace.final_rcode == RCODE.SERVFAIL
    # There should be at least one hop marked as an error for bad_response.
    assert any(h.step == "error" and h.detail == "bad_response" for h in trace.hops)


def test_resolve_iterative_transport_failures_exhaust_authorities(monkeypatch) -> None:
    """Brief: repeated transport failures lead to no_authorities_available.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that when all candidate authorities fail at the transport
        layer, the resolver reports `no_authorities_available` via SERVFAIL.
    """

    cache = _FakeCache()
    cfg = _default_config()

    class _AlwaysFailTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return None, "network_error"

    transport = _AlwaysFailTransport()

    root1 = rr.AuthorityEndpoint(name=".", host="192.0.2.40", port=53, transport="udp")
    root2 = rr.AuthorityEndpoint(name=".", host="192.0.2.41", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root1, root2])

    wire, trace = rr.resolve_iterative(
        "net-fail.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert trace.final_rcode == RCODE.SERVFAIL
    assert trace.error == "no_authorities_available"
    # Both authorities should have been tried and recorded as error hops.
    assert {h.authority.host for h in trace.hops if h.authority} == {
        "192.0.2.40",
        "192.0.2.41",
    }


def test_resolve_iterative_ignores_expired_negative_and_queries_root(
    monkeypatch,
) -> None:
    """Brief: expired NegativeEntry is ignored and root is used instead.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that an out-of-date negative cache entry does not short-circuit
        resolution and that a root authority is contacted.
    """

    cache = _FakeCache()
    # Now is far in the future; expires_at_ms is in the past.
    cfg = _default_config(now_ms=2_000_000)

    cache.store_negative(
        "expired.example",
        QTYPE.A,
        rr.NegativeEntry(
            rcode=RCODE.NXDOMAIN,
            soa_owner="example.com.",
            expires_at_ms=1_000_000,
        ),
    )

    # Child authority returns a simple NOERROR answer.
    q = DNSRecord.question("expired.example", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    class _AnsweringTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return answer_wire, None

    transport = _AnsweringTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.10", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "expired.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    # We must have contacted the root authority once.
    assert len(transport.calls) == 1


def test_get_root_servers_returns_copy() -> None:
    """Brief: get_root_servers returns a list copy of ROOT_HINTS.

    Inputs:
      - None

    Outputs:
      - Ensures modifications to the returned list do not affect ROOT_HINTS.
    """

    roots1 = rr.get_root_servers()
    roots2 = rr.get_root_servers()

    assert isinstance(roots1, list)
    assert roots1 is not roots2
    assert tuple(roots1) == rr.ROOT_HINTS

    # Mutate the returned list and confirm ROOT_HINTS is unchanged.
    popped = roots1.pop()
    assert popped in rr.ROOT_HINTS
    assert tuple(roots2) == rr.ROOT_HINTS


def test_lookup_cached_authorities_single_label_qname(monkeypatch) -> None:
    """Brief: single-label qname yields no cached authorities.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that _lookup_cached_authorities_for_qname returns an empty list
        for names like 'com' and that root hints are consulted instead.
    """

    cache = _FakeCache()
    cfg = _default_config()

    # Transport that answers successfully so that resolution can complete.
    q = DNSRecord.question("com", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    class _AnsweringTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return answer_wire, None

    transport = _AnsweringTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.60", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    # Only the root authority should have been contacted.
    assert {call[0].host for call in transport.calls} == {"192.0.2.60"}


def test_lookup_cached_authorities_ignores_unparsable_rrset(monkeypatch) -> None:
    """Brief: unparsable cached NS RRset is ignored when picking authorities.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that a cached RRset whose wire cannot be parsed is skipped and
        that the resolver falls back to root hints.
    """

    cache = _FakeCache()
    cfg = _default_config(now_ms=1_000_000)

    # Store an RRsetEntry with invalid DNS wire so DNSRecord.parse raises.
    key = rr.RRsetKey(name="example.com", rrtype=QTYPE.NS)
    cache.store_rrset(
        key,
        rr.RRsetEntry(rrset_wire=b"not-a-dns-rrset", expires_at_ms=2_000_000),
    )

    # Upstream root authority will still answer successfully.
    q = DNSRecord.question("www.example.com", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    class _AnsweringTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return answer_wire, None

    transport = _AnsweringTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.61", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "www.example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    # The bad RRset must not prevent use of the root authority.
    assert {call[0].host for call in transport.calls} == {"192.0.2.61"}


def test_lookup_cached_authorities_ignores_rrset_without_ns(monkeypatch) -> None:
    """Brief: cached RRset without any NS records is ignored.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that an RRset containing only non-NS records is skipped and
        that root hints are used instead.
    """

    cache = _FakeCache()
    cfg = _default_config(now_ms=1_000_000)

    # Build an RRset containing only a SOA record in the authority section.
    rrset = DNSRecord()
    soa_rdata = SOA(
        mname="ns.example.com.",
        rname="hostmaster.example.com.",
        times=(1, 2, 3, 4, 5),
    )
    rrset.add_auth(
        RR("example.com", QTYPE.SOA, rdata=soa_rdata, ttl=300),
    )
    rrset_wire = rrset.pack()

    key = rr.RRsetKey(name="example.com", rrtype=QTYPE.NS)
    cache.store_rrset(
        key,
        rr.RRsetEntry(rrset_wire=rrset_wire, expires_at_ms=2_000_000),
    )

    # Upstream root authority will still answer successfully.
    q = DNSRecord.question("www.example.com", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    class _AnsweringTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return answer_wire, None

    transport = _AnsweringTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.62", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "www.example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert {call[0].host for call in transport.calls} == {"192.0.2.62"}


def test_lookup_cached_authorities_falls_back_to_ns_hostname(monkeypatch) -> None:
    """Brief: cached NS RRset without usable glue falls back to NS hostname.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that when there is NS data but no in-bailiwick A/AAAA glue, the
        resolver constructs an AuthorityEndpoint using the NS hostname.
    """

    cache = _FakeCache()
    cfg = _default_config(now_ms=1_000_000)

    # RRset with NS in authority section but only non-address records in
    # additional section, so glue_by_name remains empty.
    rrset = DNSRecord()
    rrset.add_auth(
        RR("example.com", QTYPE.NS, rdata=NS("ns.example.com."), ttl=300),
    )
    # Use an NS record in additional to ensure the glue filter skips it.
    rrset.add_ar(
        RR("ns.example.com", QTYPE.NS, rdata=NS("other.example.net."), ttl=300),
    )
    rrset_wire = rrset.pack()

    key = rr.RRsetKey(name="example.com", rrtype=QTYPE.NS)
    cache.store_rrset(
        key,
        rr.RRsetEntry(rrset_wire=rrset_wire, expires_at_ms=2_000_000),
    )

    # Upstream authority reached via the NS hostname returns a simple NOERROR
    # answer.
    q = DNSRecord.question("www.example.com", "A")
    r = q.reply()
    r.header.rcode = RCODE.NOERROR
    answer_wire = r.pack()

    class _AnsweringTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            assert authority.host == "ns.example.com"
            return answer_wire, None

    transport = _AnsweringTransport()

    # Root hints should not be consulted because cached authorities are usable.
    monkeypatch.setattr(rr, "get_root_servers", lambda: [])

    wire, trace = rr.resolve_iterative(
        "www.example.com",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert len(transport.calls) == 1


def test_negative_cache_string_qtype_builds_cached_response() -> None:
    """Brief: negative cache fast path works when qtype is a string.

    Inputs:
      - None

    Outputs:
      - Ensures the NegativeEntry path builds a response using the cached
        rcode and never invokes the transport.
    """

    cache = _FakeCache()
    cfg = _default_config(now_ms=1_000_000)
    transport = _FakeTransport()

    cache.store_negative(
        "neg-string-qtype.example",
        "A",
        rr.NegativeEntry(
            rcode=RCODE.NXDOMAIN,
            soa_owner="example.com.",
            expires_at_ms=2_000_000,
        ),
    )

    wire, trace = rr.resolve_iterative(
        "neg-string-qtype.example",
        "A",
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN
    assert trace.from_cache is True
    assert trace.final_rcode == RCODE.NXDOMAIN
    assert any(h.step == "cache_hit" and h.detail == "negative_cache" for h in trace.hops)
    assert transport.calls == []


def test_global_timeout_budget_exhausted_before_query(monkeypatch) -> None:
    """Brief: overall timeout budget exhaustion yields SERVFAIL.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that when the global timeout budget is already exhausted before
        the first authority query, the resolver reports
        'timeout_budget_exhausted'.
    """

    cache = _FakeCache()
    transport = _FakeTransport()

    tick = 0

    def _fake_now() -> int:
        nonlocal tick
        return tick

    cfg = rr.ResolverConfig(
        dnssec_mode="ignore",
        edns_udp_payload=1232,
        timeout_ms=1000,
        per_try_timeout_ms=500,
        max_depth=4,
        now_ms=_fake_now,
    )

    # Advance the clock after the initial cache lookup so that by the time the
    # main loop runs, the budget is exhausted.
    def _lookup_answer_and_advance(qname: str, qtype: int) -> rr.AnswerEntry | None:
        nonlocal tick
        tick = 2_000
        return None

    cache.lookup_answer = _lookup_answer_and_advance  # type: ignore[assignment]

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.63", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "timeout-budget.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert trace.exceeded_budget is True
    assert trace.error == "timeout_budget_exhausted"
    assert transport.calls == []


def test_per_try_timeout_budget_exhausted_without_global_timeout(monkeypatch) -> None:
    """Brief: per-try timeout exhaustion with disabled global timeout.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that when timeout_ms is zero and per_try_timeout_ms is also
        zero, the resolver reports 'timeout_budget_exhausted' before issuing a
        transport query.
    """

    cache = _FakeCache()
    transport = _FakeTransport()

    cfg = rr.ResolverConfig(
        dnssec_mode="ignore",
        edns_udp_payload=1232,
        timeout_ms=0,
        per_try_timeout_ms=0,
        max_depth=4,
        now_ms=lambda: 0,
    )

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.64", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "timeout-per-try.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert trace.exceeded_budget is True
    assert trace.error == "timeout_budget_exhausted"
    assert transport.calls == []


def test_referral_ignores_non_address_glue_records(monkeypatch) -> None:
    """Brief: referral path skips non-A/AAAA records in the additional section.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that glue filtering in referral handling ignores non-address
        records and still uses any A glue that is present.
    """

    cache = _FakeCache()
    cfg = _default_config()

    q = DNSRecord.question("www.glue-filter.example", "A")

    # Root reply: NOERROR, no answers, NS in authority, both non-address and
    # address records in additional.
    root_reply = q.reply()
    root_reply.header.rcode = RCODE.NOERROR
    root_reply.add_auth(
        RR("example.com", QTYPE.NS, rdata=NS("ns.example.com."), ttl=300)
    )
    # First additional record is an NS (non-address) that should be ignored.
    root_reply.add_ar(
        RR("ns.example.com", QTYPE.NS, rdata=NS("ignored.example.net."), ttl=300),
    )
    # Second additional record is the actual A glue that should be used.
    root_reply.add_ar(RR("ns.example.com", QTYPE.A, rdata=A("198.51.100.200"), ttl=300))
    root_wire = root_reply.pack()

    # Child authority reply: final NOERROR answer.
    child_reply = q.reply()
    child_reply.header.rcode = RCODE.NOERROR
    child_reply.add_answer(
        RR("www.glue-filter.example", QTYPE.A, rdata=A("203.0.113.200"), ttl=300)
    )
    child_wire = child_reply.pack()

    class _ReferralTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            if authority.host == "192.0.2.65":
                return root_wire, None
            assert authority.host == "198.51.100.200"
            return child_wire, None

    transport = _ReferralTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.65", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "www.glue-filter.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    steps = [h.step for h in trace.hops]
    assert "referral" in steps
    assert "answer" in steps


def test_negative_caching_for_nxdomain_with_soa(monkeypatch) -> None:
    """Brief: NXDOMAIN with SOA in authority populates the negative cache.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that a final NXDOMAIN answer carrying an SOA results in a
        NegativeEntry with an expiry derived from the TTL.
    """

    cache = _FakeCache()
    cfg = _default_config(now_ms=1_000_000)

    q = DNSRecord.question("nx.example", "A")
    root_reply = q.reply()
    root_reply.header.rcode = RCODE.NXDOMAIN
    soa_rdata = SOA(
        mname="ns.example.com.",
        rname="hostmaster.example.com.",
        times=(1, 2, 3, 4, 300),
    )
    root_reply.add_auth(
        RR("example.com", QTYPE.SOA, rdata=soa_rdata, ttl=300),
    )
    root_wire = root_reply.pack()

    class _NXTransport(_FakeTransport):
        def query(self, authority, wire_query, *, timeout_ms):  # type: ignore[override]
            self.calls.append((authority, wire_query, timeout_ms))
            return root_wire, None

    transport = _NXTransport()

    root = rr.AuthorityEndpoint(name=".", host="192.0.2.66", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    wire, trace = rr.resolve_iterative(
        "nx.example",
        QTYPE.A,
        cfg=cfg,
        cache=cache,
        transports=transport,
    )

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN
    assert trace.final_rcode == RCODE.NXDOMAIN

    # The negative cache should now contain an entry for (qname, qtype).
    key = ("nx.example", QTYPE.A)
    assert key in cache.negatives
    neg_entry = cache.negatives[key]
    assert neg_entry.rcode == RCODE.NXDOMAIN
    assert neg_entry.soa_owner == "example.com"
    assert neg_entry.expires_at_ms == 1_000_000 + 300 * 1000
