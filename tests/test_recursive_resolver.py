"""
Brief: Tests for the RecursiveResolver iterative recursion logic.

Inputs:
  - None (pytest harness)

Outputs:
  - None (pytest assertions on resolution behaviour).
"""

from typing import Any

import pytest
from dnslib import A, NS, QTYPE, RCODE, RR, SOA, DNSRecord

from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
from foghorn.recursive_resolver import RecursiveResolver


def _make_nxdomain_with_soa(qname: str) -> bytes:
    """Brief: Helper to build NXDOMAIN response with SOA for qname.

    Inputs:
      - qname: Query name as text.

    Outputs:
      - Wire-format DNS response bytes with NXDOMAIN and SOA authority.
    """

    q = DNSRecord.question(qname, "A")
    r = q.reply()
    r.header.rcode = RCODE.NXDOMAIN
    r.add_auth(
        RR(
            qname,
            QTYPE.SOA,
            rdata=SOA(
                f"ns.{qname}.",
                f"hostmaster.{qname}.",
                (1, 300, 300, 300, 300),
            ),
            ttl=300,
        )
    )
    return r.pack()


def test_recursive_resolver_positive_referral_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: RecursiveResolver walks root -> TLD -> auth using NS+glue.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture to stub udp_query.

    Outputs:
      - Final NOERROR answer for www.example.com and upstream id of auth server.
    """

    # Synthetic authorities used in the referral chain. We patch the
    # initial server list to contain a single synthetic root so the test is
    # deterministic and does not depend on the baked-in root hints.
    import foghorn.recursive_resolver as rr_mod

    root_ip = "192.0.2.1"
    tld_ip = "203.0.113.10"
    auth_ip = "203.0.113.20"

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single synthetic root server for deterministic tests."""

        return [rr_mod._Server(root_ip, 53)]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return synthetic responses for root, TLD, and auth servers."""

        q = DNSRecord.parse(wire)
        qname = str(q.questions[0].qname).rstrip(".")

        if host == root_ip:
            # Root: refer to .com with NS and glue
            r = q.reply()
            r.add_auth(RR("com", QTYPE.NS, rdata=NS("ns1.com."), ttl=300))
            r.add_ar(RR("ns1.com.", QTYPE.A, rdata=A(tld_ip), ttl=300))
            return r.pack()

        if host == tld_ip:
            # TLD: refer to example.com with NS and glue
            r = q.reply()
            r.add_auth(
                RR("example.com", QTYPE.NS, rdata=NS("ns1.example.com."), ttl=300)
            )
            r.add_ar(RR("ns1.example.com.", QTYPE.A, rdata=A(auth_ip), ttl=300))
            return r.pack()

        if host == auth_ip:
            # Authoritative: final A answer
            r = q.reply()
            r.add_answer(RR(qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
            return r.pack()

        # Unexpected host: treat as NXDOMAIN to fail clearly in tests.
        return _make_nxdomain_with_soa(qname)

    # Patch the udp_query used inside recursive_resolver.
    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    # Ensure TCP is never required in this happy-path test.
    def _boom_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError("tcp_query should not be used in this test")

    monkeypatch.setattr(rr_mod, "tcp_query", _boom_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=8,
        timeout_ms=5000,
        per_try_timeout_ms=1000,
    )

    req = DNSRecord.question("www.example.com.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("93.184.216.34") for rr in resp.rr)
    assert upstream == f"{auth_ip}:53"


def test_recursive_resolver_nxdomain_terminates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: RecursiveResolver returns NXDOMAIN directly from first authority.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture to stub udp_query.

    Outputs:
      - NXDOMAIN reply and upstream id for the first authority.
    """

    # Use a fixed synthetic root for determinism.
    root_ip = "192.0.2.1"

    import foghorn.recursive_resolver as rr_mod

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single synthetic root server for NXDOMAIN test."""

        return [rr_mod._Server(root_ip, 53)]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return NXDOMAIN with SOA for any root hit."""

        q = DNSRecord.parse(wire)
        qname = str(q.questions[0].qname).rstrip(".")

        if host == root_ip:
            return _make_nxdomain_with_soa(qname)

        return _make_nxdomain_with_soa(qname)

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    def _noop_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        return _make_nxdomain_with_soa("nxdomain.example")

    monkeypatch.setattr(rr_mod, "tcp_query", _noop_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=4,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("nxdomain.example.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN
    assert upstream is not None


def test_recursive_resolver_qname_minimization(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: RecursiveResolver uses minimized QNAMEs for NS lookups.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that root is queried for "com." NS and TLD for
        "example.com." NS before the final full QNAME A lookup.
    """

    import foghorn.recursive_resolver as rr_mod

    root_ip = "192.0.2.1"
    tld_ip = "203.0.113.10"
    auth_ip = "203.0.113.20"

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single synthetic root server for deterministic tests."""

        return [rr_mod._Server(root_ip, 53)]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    seen = {"root": None, "tld": None, "auth": None}

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Inspect QNAME/QTYPE at each stage and return synthetic responses."""

        q = DNSRecord.parse(wire)
        qn = str(q.questions[0].qname)
        qt = q.questions[0].qtype

        if host == root_ip:
            seen["root"] = (qn, qt)
            # Root referral to .com
            r = q.reply()
            r.add_auth(RR("com.", QTYPE.NS, rdata=NS("ns1.com."), ttl=300))
            r.add_ar(RR("ns1.com.", QTYPE.A, rdata=A(tld_ip), ttl=300))
            return r.pack()

        if host == tld_ip:
            seen["tld"] = (qn, qt)
            # TLD referral to example.com
            r = q.reply()
            r.add_auth(
                RR("example.com.", QTYPE.NS, rdata=NS("ns1.example.com."), ttl=300)
            )
            r.add_ar(RR("ns1.example.com.", QTYPE.A, rdata=A(auth_ip), ttl=300))
            return r.pack()

        if host == auth_ip:
            seen["auth"] = (qn, qt)
            # Final A answer
            r = q.reply()
            r.add_answer(
                RR("www.example.com.", QTYPE.A, rdata=A("93.184.216.34"), ttl=300)
            )
            return r.pack()

        return _make_nxdomain_with_soa(qn)

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    def _boom_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError("tcp_query should not be used in qname minimization test")

    monkeypatch.setattr(rr_mod, "tcp_query", _boom_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=8,
        timeout_ms=5000,
        per_try_timeout_ms=1000,
    )

    req = DNSRecord.question("www.example.com.", "A")
    wire, upstream = resolver.resolve(req)
    resp = DNSRecord.parse(wire)

    # Ensure final answer is correct.
    assert resp.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("93.184.216.34") for rr in resp.rr)
    assert upstream == f"{auth_ip}:53"

    # Check QNAME minimization stages.
    assert seen["root"] is not None
    root_qname, root_qtype = seen["root"]
    assert root_qname == "com."
    assert root_qtype == QTYPE.NS

    assert seen["tld"] is not None
    tld_qname, tld_qtype = seen["tld"]
    assert tld_qname == "example.com."
    assert tld_qtype == QTYPE.NS

    assert seen["auth"] is not None
    auth_qname, auth_qtype = seen["auth"]
    assert auth_qname == "www.example.com."
    assert auth_qtype == QTYPE.A


def test_udp_and_tcp_query_wrappers_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: udp_query/tcp_query wrappers delegate to transport helpers.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture for stubbing transport calls.

    Outputs:
      - Asserts that both wrappers call the underlying transport functions
        with the expected arguments and return values.
    """

    import foghorn.recursive_resolver as rr_mod

    udp_called = {}

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return a fixed UDP response and record call arguments."""

        udp_called["args"] = (host, port, wire, timeout_ms)
        return b"udp-response"

    tcp_called = {}

    def fake_tcp_query(
        host: str,
        port: int,
        wire: bytes,
        *,
        connect_timeout_ms: int = 0,
        read_timeout_ms: int = 0,
    ) -> bytes:  # noqa: D401, ANN001
        """Return a fixed TCP response and record call arguments."""

        tcp_called["args"] = (
            host,
            port,
            wire,
            connect_timeout_ms,
            read_timeout_ms,
        )
        return b"tcp-response"

    monkeypatch.setattr(rr_mod, "_udp_transport_query", fake_udp_query)
    monkeypatch.setattr(rr_mod, "_tcp_transport_query", fake_tcp_query)

    wire = b"query-bytes"

    udp_out = rr_mod.udp_query("192.0.2.10", 5353, wire, timeout_ms=1234)
    tcp_out = rr_mod.tcp_query(
        "192.0.2.20",
        853,
        wire,
        connect_timeout_ms=150,
        read_timeout_ms=250,
    )

    assert udp_out == b"udp-response"
    assert udp_called["args"] == ("192.0.2.10", 5353, wire, 1234)

    assert tcp_out == b"tcp-response"
    assert tcp_called["args"] == (
        "192.0.2.20",
        853,
        wire,
        150,
        250,
    )


def test_default_root_hints_and_choose_initial_servers() -> None:
    """Brief: _default_root_hints and _choose_initial_servers return servers.

    Inputs:
      - None (direct helper calls).

    Outputs:
      - Non-empty lists of _Server instances suitable as initial authorities.
    """

    import foghorn.recursive_resolver as rr_mod

    hints = rr_mod._default_root_hints()
    assert hints
    assert all(isinstance(s, rr_mod._Server) for s in hints)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=4,
        timeout_ms=2000,
        per_try_timeout_ms=1000,
    )

    servers = resolver._choose_initial_servers()
    assert servers
    assert all(isinstance(s, rr_mod._Server) for s in servers)


def test_query_single_udp_and_tcp_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _query_single performs UDP query with TCP fallback on TC=1.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures _query_single hits UDP, then TCP when TC is set, and returns
        the TCP response bytes.
    """

    import foghorn.recursive_resolver as rr_mod

    udp_calls: list[tuple[str, int, bytes, int]] = []
    tcp_calls: list[tuple[str, int, bytes, int, int]] = []

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return a reply with TC=1 set to trigger TCP fallback."""

        udp_calls.append((host, port, wire, timeout_ms))
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.header.tc = 1
        return r.pack()

    def fake_tcp_query(
        host: str,
        port: int,
        wire: bytes,
        *,
        connect_timeout_ms: int = 0,
        read_timeout_ms: int = 0,
    ) -> bytes:  # noqa: D401, ANN001
        """Return a final NOERROR A answer over TCP."""

        tcp_calls.append((host, port, wire, connect_timeout_ms, read_timeout_ms))
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.add_answer(
            RR(str(q.questions[0].qname), QTYPE.A, rdata=A("198.51.100.10"), ttl=60)
        )
        return r.pack()

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)
    monkeypatch.setattr(rr_mod, "tcp_query", fake_tcp_query)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=2,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    server = rr_mod._Server("192.0.2.1", 53)
    req = DNSRecord.question("example.test.", "A")
    resp_wire = resolver._query_single(server, req.pack())

    assert udp_calls
    assert tcp_calls

    resp = DNSRecord.parse(resp_wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("198.51.100.10") for rr in resp.rr)


def test_extract_next_servers_edge_cases() -> None:
    """Brief: _extract_next_servers handles non-address and bad glue records.

    Inputs:
      - None (direct call with a synthetic response-like object).

    Outputs:
      - No servers are returned when glue is non-A/AAAA or has bad rdata.
    """

    class _FakeNS:
        def __init__(self, name: str) -> None:
            self.rtype = QTYPE.NS
            self.rdata = type("RData", (), {"label": name})()

    class _BadRData:
        def __str__(self) -> str:  # noqa: D401
            """Raise to trigger the rdata exception path."""

            raise RuntimeError("bad rdata")

    class _FakeGlue:
        def __init__(self, name: str, rtype: int, bad: bool = False) -> None:
            self.rtype = rtype
            self.rname = name
            self.rdata = _BadRData() if bad else "198.51.100.10"

    class _Resp:
        def __init__(self) -> None:
            self.auth = [_FakeNS("ns.example.com.")]
            # First glue is non-A/AAAA; second is A but with bad rdata.
            self.ar = [
                _FakeGlue("ns.example.com.", QTYPE.MX),
                _FakeGlue("ns.example.com.", QTYPE.A, bad=True),
            ]

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=4,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    servers = resolver._extract_next_servers(_Resp())
    assert servers == []


def test_resolve_root_qname_no_servers_synthesizes_servfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve() with no servers returns a synthesized SERVFAIL.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - SERVFAIL reply when _choose_initial_servers returns an empty list.
    """

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return no servers to force immediate SERVFAIL."""

        return []

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=1000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question(".", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert upstream is None


def test_resolve_counts_leading_underscore_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve() processes leading underscore labels without error.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - SERVFAIL reply with no upstream when there are no servers, ensuring the
        underscore-prefix counting path is exercised.
    """

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return no servers so only name-processing logic runs."""

        return []

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=1000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("_service._tcp.example.com.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert upstream is None


def test_resolve_honours_overall_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: resolve() stops when the overall deadline has passed.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - SERVFAIL reply with no upstream and no network calls when the clock
        already exceeds the computed deadline.
    """

    import foghorn.recursive_resolver as rr_mod

    root = rr_mod._Server("192.0.2.1", 53)

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single root server to exercise the deadline check."""

        return [root]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    # First call (for deadline) returns an early time; second call (in loop)
    # returns a much later time to force now >= deadline.
    times = [1000.0, 1005.0]

    def fake_time() -> float:  # noqa: D401
        """Return deterministic timestamps for deadline tests."""

        return times.pop(0)

    monkeypatch.setattr(rr_mod.time, "time", fake_time)

    def _boom_udp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError(
            "udp_query should not be reached when deadline is exceeded"
        )

    monkeypatch.setattr(rr_mod, "udp_query", _boom_udp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("deadline.example.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert upstream is None


def test_resolve_visited_loop_guard_and_delegation_follow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve() uses visited set and follows delegations via NS glue.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - SERVFAIL reply after revisiting the same (qname, host) pair, exercising
        the visited-set guard and final-stage delegation handling.
    """

    import foghorn.recursive_resolver as rr_mod

    root = rr_mod._Server("192.0.2.1", 53)

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single root server for deterministic visited-set tests."""

        return [root]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return a NOERROR reply with no answers or NS records."""

        assert host == root.host
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.header.rcode = RCODE.NOERROR
        return r.pack()

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    def fake_extract_next_servers(self, resp: DNSRecord) -> list[Any]:  # noqa: D401
        """Always return the same server to create a small delegation loop."""

        assert isinstance(resp, DNSRecord)
        return [root]

    monkeypatch.setattr(
        RecursiveResolver, "_extract_next_servers", fake_extract_next_servers
    )

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question(".", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert upstream == f"{root.host}:{root.port}"


def test_resolve_tcp_fallback_on_tc_in_main_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve() falls back to TCP when TC=1 is set in a response.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Final answer is derived from the TCP response and tcp_query is called
        at least once.
    """

    import foghorn.recursive_resolver as rr_mod

    root = rr_mod._Server("192.0.2.1", 53)

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single root server to exercise TC handling."""

        return [root]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return a reply with TC=1 to trigger TCP fallback."""

        assert host == root.host
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.header.tc = 1
        return r.pack()

    tcp_called: dict[str, Any] = {}

    def fake_tcp_query(
        host: str,
        port: int,
        wire: bytes,
        *,
        connect_timeout_ms: int = 0,
        read_timeout_ms: int = 0,
    ) -> bytes:  # noqa: D401, ANN001
        """Return a final NOERROR A answer and record the call."""

        tcp_called["args"] = (
            host,
            port,
            connect_timeout_ms,
            read_timeout_ms,
        )
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.add_answer(
            RR(str(q.questions[0].qname), QTYPE.A, rdata=A("198.51.100.42"), ttl=60)
        )
        return r.pack()

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)
    monkeypatch.setattr(rr_mod, "tcp_query", fake_tcp_query)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("tc-fallback.example.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("198.51.100.42") for rr in resp.rr)
    assert upstream == f"{root.host}:{root.port}"
    assert tcp_called


def test_resolve_noerror_nodata_with_soa_returns_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve() returns NOERROR+SOA NODATA responses directly.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Final response is the upstream NOERROR NODATA with SOA authority.
    """

    import foghorn.recursive_resolver as rr_mod

    root = rr_mod._Server("192.0.2.1", 53)

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single root server for NODATA tests."""

        return [root]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return NOERROR with empty answers and an SOA in authority."""

        assert host == root.host
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.header.rcode = RCODE.NOERROR
        r.add_auth(
            RR(
                str(q.questions[0].qname),
                QTYPE.SOA,
                rdata=SOA(
                    "ns.example.",
                    "hostmaster.example.",
                    (1, 300, 300, 300, 300),
                ),
                ttl=300,
            )
        )
        return r.pack()

    def _boom_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError("tcp_query should not be used for NOERROR NODATA SOA")

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)
    monkeypatch.setattr(rr_mod, "tcp_query", _boom_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("nodata.example.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert not resp.rr
    assert any(rr.rtype == QTYPE.SOA for rr in resp.auth)
    assert upstream == f"{root.host}:{root.port}"


def test_resolve_final_fallthrough_without_delegation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve() returns final response when no delegation is present.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Upstream SERVFAIL with no NS-based delegation is returned as-is.
    """

    import foghorn.recursive_resolver as rr_mod

    root = rr_mod._Server("192.0.2.1", 53)

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single root server for fallthrough tests."""

        return [root]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return a SERVFAIL reply with no delegation information."""

        assert host == root.host
        q = DNSRecord.parse(wire)
        r = q.reply()
        r.header.rcode = RCODE.SERVFAIL
        return r.pack()

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=3,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("fallthrough.example.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert upstream == f"{root.host}:{root.port}"
