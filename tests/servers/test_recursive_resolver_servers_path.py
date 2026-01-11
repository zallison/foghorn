"""
Brief: Tests for foghorn.servers.recursive_resolver to ensure coverage of
       the servers-path RecursiveResolver implementation.

Inputs:
  - None (pytest harness).

Outputs:
  - None (assertions on recursive resolution behaviour and helpers).
"""

from typing import Any

import pytest
from dnslib import A, NS, QTYPE, RCODE, RR, SOA, DNSRecord

from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
import foghorn.servers.recursive_resolver as rr_mod
from foghorn.servers.recursive_resolver import RecursiveResolver


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


def test_servers_recursive_udp_and_tcp_wrappers_delegate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: udp_query/tcp_query wrappers in servers path delegate to transports.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture for stubbing transport calls.

    Outputs:
      - Asserts that both wrappers call the underlying transport helpers with
        the expected arguments and return values.
    """

    udp_called: dict[str, Any] = {}

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return a fixed UDP response and record call arguments."""

        udp_called["args"] = (host, port, wire, timeout_ms)
        return b"udp-response"

    tcp_called: dict[str, Any] = {}

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


def test_servers_default_root_hints_and_choose_initial_servers() -> None:
    """Brief: _default_root_hints and _choose_initial_servers work in servers path.

    Inputs:
      - None (direct helper calls).

    Outputs:
      - Non-empty lists of _Server instances suitable as initial authorities.
    """

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


def test_servers_query_single_udp_and_tcp_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _query_single in servers path performs UDP query with TCP fallback.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures _query_single hits UDP, then TCP when TC is set, and returns the
        TCP response bytes.
    """

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


def test_servers_recursive_resolver_positive_referral_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: servers RecursiveResolver walks root -> TLD -> auth using NS+glue.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture to stub udp_query/tcp_query.

    Outputs:
      - Final NOERROR answer for www.example.com and upstream id of auth server.
    """

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

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    def _boom_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError("tcp_query should not be used in this positive-chain test")

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


def test_servers_resolve_root_qname_no_servers_synthesizes_servfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: servers resolve() with no servers returns a synthesized SERVFAIL.

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
